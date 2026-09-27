use crate::{
    field::{self, Element, MODULUS, ONE, Transform, ZERO, base},
    oracles::{coset, extension_values, masked_base_coefficients},
    parameters::*,
    rows::RowShards,
    sums::{self, Sums},
    tree::Tree,
};
use parallel_work::{Job, MAXIMUM_JOB_BYTES, Part, Shared, submit};
use zeroize::{Zeroize, Zeroizing};

// The jobs that add the terms of the masked affine sum's values on the
// four cosets to the domain's sums. Each weight is the mask challenge,
// possibly times a public factor, so the finished sums are the values the
// oracle interpolates.

/// Adds an extension polynomial's weighted values.
pub static TERM: Job = Job {
    kind: 0x0140,
    run: add_term,
};
/// Adds a committed column's products with its weighted public column.
pub static COLUMN: Job = Job {
    kind: 0x0141,
    run: add_column,
};
/// Adds a weighted public polynomial's products with a combination of
/// committed columns.
pub static PRODUCT: Job = Job {
    kind: 0x0142,
    run: add_product,
};

const ELEMENT_BYTES: usize = 48;
const WORD_BYTES: usize = 16;
// A combined column's weight, mask and words in a product job.
const COMBINED_COLUMN_BYTES: usize = ELEMENT_BYTES + WORD_BYTES * MASKS + 2 * SYSTEMATIC;

fn number(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn word(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(bytes[..WORD_BYTES].try_into().unwrap())
}
fn elements(bytes: &[u8]) -> Vec<Element> {
    bytes
        .chunks_exact(ELEMENT_BYTES)
        .map(field::decode)
        .collect()
}
// The sums' header and the weight that begin a job's input, with room for
// the bytes that follow them.
fn start(sums: &Sums, weight: Element, room: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        sums::HEADER_BYTES + ELEMENT_BYTES + room,
    ));
    bytes.extend(sums.header());
    bytes.extend(field::encode(weight));
    bytes
}
// A job's session, weight and the bytes that follow them.
fn read_start(input: &[u8]) -> (u64, Element, &[u8]) {
    let (session, length, rest) = sums::header(input);
    assert_eq!(length, DOMAIN);
    let (weight, rest) = rest.split_at(ELEMENT_BYTES);
    (session, field::decode(weight), rest)
}

/// Starts the job that adds the weighted values of the coefficients.
pub fn term(sums: &mut Sums, weight: Element, coefficients: &[Element]) {
    let mut input = start(sums, weight, ELEMENT_BYTES * coefficients.len());
    for coefficient in coefficients {
        input.extend(field::encode(*coefficient));
    }
    sums.add(submit(&TERM, None, &[Part::Bytes(&input)], 0));
}
fn add_term(input: &[u8]) -> Vec<u8> {
    let (session, weight, rest) = read_start(input);
    let coefficients = Zeroizing::new(elements(rest));
    let transform = Transform::cached(SYSTEMATIC);
    sums::with(session, DOMAIN, |sums| {
        for index in 0..4 {
            let values = Zeroizing::new(extension_values(&coefficients, coset(index), transform));
            for (row, value) in values.iter().enumerate() {
                let position = index + 4 * row;
                sums[position] = field::add(sums[position], field::multiply(weight, *value));
            }
        }
    });
    Vec::new()
}

/// Starts the job that adds the products of the committed column of the
/// words and mask with the weighted public column of the values.
pub fn column(sums: &mut Sums, weight: Element, values: &[Element], mask: &[u128], words: &[u16]) {
    assert_eq!(
        (values.len(), mask.len(), words.len()),
        (SYSTEMATIC, MASKS, SYSTEMATIC)
    );
    let mut input = start(
        sums,
        weight,
        ELEMENT_BYTES * SYSTEMATIC + WORD_BYTES * MASKS + 2 * SYSTEMATIC,
    );
    for value in values {
        input.extend(field::encode(*value));
    }
    for value in mask {
        input.extend(value.to_le_bytes());
    }
    for value in words {
        input.extend(value.to_le_bytes());
    }
    sums.add(submit(&COLUMN, None, &[Part::Bytes(&input)], 0));
}
fn add_column(input: &[u8]) -> Vec<u8> {
    let (session, weight, rest) = read_start(input);
    let (public, rest) = rest.split_at(ELEMENT_BYTES * SYSTEMATIC);
    let (mask, words) = rest.split_at(WORD_BYTES * MASKS);
    assert_eq!(words.len(), 2 * SYSTEMATIC);
    let transform = Transform::cached(SYSTEMATIC);
    let mut public = elements(public);
    transform.extension(&mut public, true);
    for value in public.iter_mut() {
        *value = field::multiply(*value, weight);
    }
    let mask = Zeroizing::new(mask.chunks_exact(WORD_BYTES).map(word).collect::<Vec<_>>());
    let mut coefficients = Zeroizing::new(
        words
            .chunks_exact(2)
            .map(|value| u128::from(u16::from_le_bytes([value[0], value[1]])))
            .collect::<Vec<_>>(),
    );
    transform.base(&mut coefficients, true);
    sums::with(session, DOMAIN, |sums| {
        for index in 0..4 {
            let public = extension_values(&public, coset(index), transform);
            let values = Zeroizing::new(masked_base_coefficients(
                coefficients.to_vec(),
                &mask,
                coset(index),
                transform,
                None,
            ));
            for (row, (public, value)) in public.iter().zip(values.iter()).enumerate() {
                let position = index + 4 * row;
                sums[position] = field::add(sums[position], field::scale(*public, *value));
            }
        }
    });
    Vec::new()
}

/// A product job's public polynomial: a challenge's geometric sequence, or
/// adjoint values that the jobs share.
pub enum Public<'a> {
    Geometric {
        alpha: Element,
        degree: usize,
        automorphism: usize,
        shift: usize,
        constant: bool,
    },
    Adjoint {
        values: &'a Shared,
        count: usize,
    },
}
/// Starts the jobs that add the products of the weighted public
/// polynomial with the combination of the weighted committed columns of
/// the words and masks, each job combining as many columns as its input
/// holds.
pub fn products(
    sums: &mut Sums,
    weight: Element,
    public: Public,
    columns: &[(usize, Element)],
    words: &[Vec<u16>],
    masks: &[Vec<u128>],
) {
    let mut prefix = start(sums, weight, 1 + ELEMENT_BYTES + 13);
    let shared = match public {
        Public::Geometric {
            alpha,
            degree,
            automorphism,
            shift,
            constant,
        } => {
            prefix.push(0);
            prefix.extend(field::encode(alpha));
            for value in [degree, automorphism, shift] {
                prefix.extend((value as u32).to_le_bytes());
            }
            prefix.push(u8::from(constant));
            None
        }
        Public::Adjoint { values, count } => {
            assert!(count.is_power_of_two() && count <= SYSTEMATIC);
            prefix.push(1);
            prefix.extend((count as u32).to_le_bytes());
            Some((values, ELEMENT_BYTES * count))
        }
    };
    let room = MAXIMUM_JOB_BYTES - prefix.len() - shared.map_or(0, |(_, length)| length) - 4;
    for chunk in columns.chunks(room / COMBINED_COLUMN_BYTES) {
        let mut bytes = Zeroizing::new(Vec::with_capacity(4 + COMBINED_COLUMN_BYTES * chunk.len()));
        bytes.extend((chunk.len() as u32).to_le_bytes());
        for (column, weight) in chunk {
            assert_eq!(
                (masks[*column].len(), words[*column].len()),
                (MASKS, SYSTEMATIC)
            );
            bytes.extend(field::encode(*weight));
            for value in &masks[*column] {
                bytes.extend(value.to_le_bytes());
            }
            for value in &words[*column] {
                bytes.extend(value.to_le_bytes());
            }
        }
        let ticket = match shared {
            Some((values, _)) => submit(
                &PRODUCT,
                None,
                &[
                    Part::Bytes(&prefix),
                    Part::Shared(values),
                    Part::Bytes(&bytes),
                ],
                0,
            ),
            None => submit(
                &PRODUCT,
                None,
                &[Part::Bytes(&prefix), Part::Bytes(&bytes)],
                0,
            ),
        };
        sums.add(ticket);
    }
}
fn add_product(input: &[u8]) -> Vec<u8> {
    let (session, weight, rest) = read_start(input);
    let (mut coefficient, rest) = match rest[0] {
        0 => {
            let alpha = field::decode(&rest[1..1 + ELEMENT_BYTES]);
            let rest = &rest[1 + ELEMENT_BYTES..];
            let constant = match rest[12] {
                0 => false,
                1 => true,
                _ => panic!("Geometric constant"),
            };
            (
                geometric(
                    alpha,
                    number(rest),
                    number(&rest[4..]),
                    number(&rest[8..]),
                    constant,
                ),
                &rest[13..],
            )
        }
        1 => {
            let count = number(&rest[1..]);
            let (values, rest) = rest[5..].split_at(ELEMENT_BYTES * count);
            (embed(elements(values)), rest)
        }
        _ => panic!("Public polynomial"),
    };
    for value in coefficient.iter_mut() {
        *value = field::multiply(*value, weight);
    }
    let count = number(rest);
    let columns = &rest[4..];
    assert_eq!(columns.len(), COMBINED_COLUMN_BYTES * count);
    let transform = Transform::cached(SYSTEMATIC);
    let variable = Zeroizing::new(combined(columns, transform));
    sums::with(session, DOMAIN, |sums| {
        for index in 0..4 {
            let left = extension_values(&coefficient, coset(index), transform);
            let right = Zeroizing::new(extension_values(&variable, coset(index), transform));
            for (row, (left, right)) in left.into_iter().zip(right.iter()).enumerate() {
                let position = index + 4 * row;
                sums[position] = field::add(sums[position], field::multiply(left, *right));
            }
        }
    });
    Vec::new()
}
// The masked coefficients of the weighted sum of the encoded committed
// columns.
fn combined(columns: &[u8], transform: &Transform) -> Vec<Element> {
    let mut values = Zeroizing::new(Vec::with_capacity(SYSTEMATIC + MASKS));
    values.resize(SYSTEMATIC, ZERO);
    let mut masks = Zeroizing::new(vec![ZERO; MASKS]);
    for column in columns.chunks_exact(COMBINED_COLUMN_BYTES) {
        let (weight, rest) = column.split_at(ELEMENT_BYTES);
        let weight = field::decode(weight);
        let (mask, words) = rest.split_at(WORD_BYTES * MASKS);
        for (value, raw) in values.iter_mut().zip(words.chunks_exact(2)) {
            let raw = u16::from_le_bytes([raw[0], raw[1]]);
            if raw != 0 {
                *value = field::add(*value, field::scale(weight, u128::from(raw)));
            }
        }
        for (value, mask) in masks.iter_mut().zip(mask.chunks_exact(WORD_BYTES)) {
            *value = field::add(*value, field::scale(weight, word(mask)));
        }
    }
    transform.extension(&mut values, true);
    for (value, mask) in values.iter_mut().zip(masks.iter()) {
        *value = field::subtract(*value, *mask);
    }
    values.extend_from_slice(&masks);
    std::mem::take(&mut *values)
}
fn embed(mut values: Vec<Element>) -> Vec<Element> {
    let degree = values.len();
    Transform::new(degree).extension(&mut values, true);
    let stride = SYSTEMATIC / degree;
    let inverse = base::power(stride as u128, MODULUS - 2);
    let mut coefficients = vec![ZERO; SYSTEMATIC];
    for (block, value) in coefficients.iter_mut().enumerate() {
        *value = field::scale(values[block % degree], inverse);
    }
    coefficients
}
fn geometric(
    alpha: Element,
    degree: usize,
    automorphism: usize,
    shift: usize,
    constant: bool,
) -> Vec<Element> {
    if constant {
        return embed(vec![ONE; degree]);
    }
    let mut powers = Vec::with_capacity(degree);
    let mut current = ONE;
    for _ in 0..degree {
        powers.push(current);
        current = field::multiply(current, alpha);
    }
    embed(
        (0..degree)
            .map(|index| {
                let exponent = (index * automorphism + shift) % (2 * degree);
                if exponent < degree {
                    powers[exponent % degree]
                } else {
                    field::subtract(ZERO, powers[exponent % degree])
                }
            })
            .collect(),
    )
}

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
        let mut rows = RowShards::open(&tree);
        rows.absorb_extension(&quotient);
        rows.close(&mut tree);
        Self {
            target,
            claimed_sum,
            quotient: std::mem::take(&mut *quotient),
            remainder: std::mem::take(&mut *remainder),
            tree,
            lookup_weight,
        }
    }
    pub fn openings(&self, indices: &[usize]) -> Vec<Vec<u8>> {
        let transform = Transform::cached(SYSTEMATIC);
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
                transform,
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
