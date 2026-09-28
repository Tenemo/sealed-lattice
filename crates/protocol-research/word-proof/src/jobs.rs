//! Work that helper instances of the participant module run on their own.
//! Each job's output is a function of its input bytes and of the state its
//! shard's earlier jobs left, and every crate that includes this module and
//! the row shards submits the same kinds, whose functions share this source.
use crate::{
    combination,
    field::{self, Element, Transform, ZERO},
    linear_oracle,
    oracles::{
        coset, extension_values_selected, masked_base_coefficients, masked_base_polynomial,
        masked_extension_coefficients_of,
    },
    parameters::*,
    rows, sums, tree,
};
use parallel_work::{Job, StreamedRecords, gather};
use zeroize::Zeroizing;

/// A first-oracle base column's values at queried positions.
pub static FIRST_OPENINGS: Job = Job {
    kind: 0x0102,
    run: first_openings,
};
/// A second-oracle column's values at queried positions.
pub static SECOND_OPENINGS: Job = Job {
    kind: 0x0103,
    run: second_openings,
};
/// A first-oracle base column's masked coefficients.
pub static FIRST_COEFFICIENTS: Job = Job {
    kind: 0x0104,
    run: first_coefficients,
};
/// A second-oracle column's masked coefficients.
pub static SECOND_COEFFICIENTS: Job = Job {
    kind: 0x0105,
    run: second_coefficients,
};
pub static JOBS: [&Job; 22] = [
    &FIRST_OPENINGS,
    &SECOND_OPENINGS,
    &FIRST_COEFFICIENTS,
    &SECOND_COEFFICIENTS,
    &rows::OPEN,
    &rows::BASE,
    &rows::EXTENSION,
    &rows::CLOSE,
    &rows::EXPORT,
    &rows::IMPORT,
    &rows::DISCARD,
    &sums::COLLECT,
    &sums::REMOVE,
    &combination::COLUMNS,
    &combination::COUNTS,
    &combination::EXTENSION,
    &linear_oracle::TERM,
    &linear_oracle::COMBINATION,
    &linear_oracle::PRODUCT,
    &linear_oracle::PUBLIC,
    &tree::NODES,
    &tree::LEAVES,
];

const WORD_BYTES: usize = 16;
const ELEMENT_BYTES: usize = 48;

/// The output bytes of a coefficient job whose coefficients have the
/// width.
pub const fn coefficient_bytes(width: usize) -> usize {
    (WITNESS_DEGREE + 1) * width
}

/// A base column's values: the witness words, or the multiplicities.
pub enum BaseValues<'a> {
    Words(&'a [u16]),
    Counts(&'a [u128]),
}
/// A second-oracle column's values, which the job reads from the
/// reciprocal table it streams: a lookup's scaled words, or the
/// multiplicities.
pub enum SecondValues<'a> {
    Lookup { words: &'a [u16], factor: u128 },
    Counts(&'a [u128]),
}

fn word(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(bytes.try_into().unwrap())
}
fn element(bytes: &[u8]) -> Element {
    [
        word(&bytes[..16]),
        word(&bytes[16..32]),
        word(&bytes[32..48]),
    ]
}

/// A base column: its word width, mask and values, in a buffer of their
/// exact length, which no growth copies without zeroizing.
pub fn base_column(values: BaseValues, mask: &[u128]) -> Zeroizing<Vec<u8>> {
    assert_eq!(mask.len(), MASKS);
    let width = match values {
        BaseValues::Words(_) => 2,
        BaseValues::Counts(_) => WORD_BYTES,
    };
    let mut output = Zeroizing::new(Vec::with_capacity(
        1 + MASKS * WORD_BYTES + SYSTEMATIC * width,
    ));
    match values {
        BaseValues::Words(values) => {
            assert_eq!(values.len(), SYSTEMATIC);
            output.push(2);
            for value in mask {
                output.extend(value.to_le_bytes());
            }
            for value in values {
                output.extend(value.to_le_bytes());
            }
        }
        BaseValues::Counts(values) => {
            assert_eq!(values.len(), SYSTEMATIC);
            output.push(16);
            for value in mask {
                output.extend(value.to_le_bytes());
            }
            for value in values {
                output.extend(value.to_le_bytes());
            }
        }
    }
    output
}
// The mask and the transformed coefficients of an encoded base column, and
// the bytes that follow it.
fn decode_base(input: &[u8]) -> (Zeroizing<Vec<u128>>, Zeroizing<Vec<u128>>, &[u8]) {
    let width = usize::from(input[0]);
    assert!(width == 2 || width == 16);
    let (mask, rest) = input[1..].split_at(MASKS * WORD_BYTES);
    let (values, rest) = rest.split_at(SYSTEMATIC * width);
    let mask = Zeroizing::new(mask.chunks_exact(WORD_BYTES).map(word).collect::<Vec<_>>());
    let mut coefficients = Zeroizing::new(
        values
            .chunks_exact(width)
            .map(|value| {
                if width == 2 {
                    u128::from(u16::from_le_bytes(value.try_into().unwrap()))
                } else {
                    word(value)
                }
            })
            .collect::<Vec<_>>(),
    );
    Transform::cached(SYSTEMATIC).base(&mut coefficients, true);
    (mask, coefficients, rest)
}
/// A second-oracle column: its mask and values, whose reciprocals the job
/// streams from the reciprocal table, in a buffer of their exact length.
pub fn second_column(values: SecondValues, mask: &[Element]) -> Zeroizing<Vec<u8>> {
    assert_eq!(mask.len(), MASKS);
    let values_bytes = match values {
        SecondValues::Lookup { .. } => WORD_BYTES + SYSTEMATIC * 2,
        SecondValues::Counts(_) => SYSTEMATIC * WORD_BYTES,
    };
    let mut output = Zeroizing::new(Vec::with_capacity(1 + MASKS * ELEMENT_BYTES + values_bytes));
    output.push(u8::from(matches!(values, SecondValues::Counts(_))));
    for value in mask {
        output.extend(field::encode(*value));
    }
    match values {
        SecondValues::Lookup { words, factor } => {
            assert_eq!(words.len(), SYSTEMATIC);
            output.extend(factor.to_le_bytes());
            for value in words {
                output.extend(value.to_le_bytes());
            }
        }
        SecondValues::Counts(counts) => {
            assert_eq!(counts.len(), SYSTEMATIC);
            for value in counts {
                output.extend(value.to_le_bytes());
            }
        }
    }
    output
}
/// The reciprocal table that each second-oracle column's jobs stream.
pub fn reciprocal_table(inverses: &[Element]) -> Zeroizing<Vec<u8>> {
    assert_eq!(inverses.len(), SYSTEMATIC);
    let mut output = Zeroizing::new(Vec::with_capacity(SYSTEMATIC * ELEMENT_BYTES));
    for value in inverses {
        output.extend(field::encode(*value));
    }
    output
}
// The masked coefficients of an encoded second-oracle column, whose
// reciprocals the job streams: the multiplicities scale the table's in
// order, and a lookup's scaled words gather theirs a chunk of the table at
// a time. Returns them with the bytes that follow the column.
fn decode_second(input: &[u8]) -> (Zeroizing<Vec<Element>>, &[u8]) {
    assert_eq!(
        parallel_work::streamed_length(),
        SYSTEMATIC * ELEMENT_BYTES,
        "Reciprocal table length"
    );
    let counts = match input[0] {
        0 => false,
        1 => true,
        _ => panic!("Second column mode"),
    };
    let (mask, rest) = input[1..].split_at(MASKS * ELEMENT_BYTES);
    let mask = Zeroizing::new(
        mask.chunks_exact(ELEMENT_BYTES)
            .map(element)
            .collect::<Vec<_>>(),
    );
    let mut values = Zeroizing::new(Vec::with_capacity(SYSTEMATIC + MASKS));
    let rest = if counts {
        let (counts, rest) = rest.split_at(SYSTEMATIC * WORD_BYTES);
        let mut table = StreamedRecords::new(ELEMENT_BYTES, SYSTEMATIC);
        values.extend(
            counts
                .chunks_exact(WORD_BYTES)
                .enumerate()
                .map(|(index, count)| field::scale(element(table.record(index)), word(count))),
        );
        rest
    } else {
        let factor = word(&rest[..WORD_BYTES]) as usize;
        let (words, rest) = rest[WORD_BYTES..].split_at(SYSTEMATIC * 2);
        values.resize(SYSTEMATIC, ZERO);
        gather(
            ELEMENT_BYTES,
            SYSTEMATIC,
            |position| {
                usize::from(u16::from_le_bytes([
                    words[2 * position],
                    words[2 * position + 1],
                ])) * factor
            },
            |position, record| values[position] = element(record),
        );
        rest
    };
    let coefficients =
        masked_extension_coefficients_of(values, &mask, Transform::cached(SYSTEMATIC));
    (Zeroizing::new(coefficients), rest)
}
/// Each coset's queried positions, each list preceded by its count.
pub fn positions(groups: &[Vec<(usize, usize)>; 4]) -> Vec<u8> {
    let mut output = Vec::new();
    for selected in groups {
        output.extend((selected.len() as u32).to_le_bytes());
        for (_, position) in selected {
            output.extend((*position as u32).to_le_bytes());
        }
    }
    output
}
// The positions that begin a job's input, and the bytes that follow them.
fn decode_positions(mut input: &[u8]) -> ([Vec<usize>; 4], &[u8]) {
    let groups = std::array::from_fn(|_| {
        let count = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let positions = input[4..4 + 4 * count]
            .chunks_exact(4)
            .map(|position| u32::from_le_bytes(position.try_into().unwrap()) as usize)
            .collect::<Vec<_>>();
        assert!(positions.iter().all(|position| *position < SYSTEMATIC));
        input = &input[4 + 4 * count..];
        positions
    });
    (groups, input)
}

/// Each coset's queried values in its positions' order.
fn first_openings(input: &[u8]) -> Vec<u8> {
    let (groups, rest) = decode_positions(input);
    let (mask, coefficients, rest) = decode_base(rest);
    assert!(rest.is_empty());
    let mut output = Vec::new();
    for (coset_index, positions) in groups.iter().enumerate() {
        if positions.is_empty() {
            continue;
        }
        for value in masked_base_coefficients(
            coefficients.to_vec(),
            &mask,
            coset(coset_index),
            Transform::cached(SYSTEMATIC),
            Some(positions.as_slice()),
        ) {
            output.extend(value.to_le_bytes());
        }
    }
    output
}
fn second_openings(input: &[u8]) -> Vec<u8> {
    let (groups, rest) = decode_positions(input);
    let (coefficients, rest) = decode_second(rest);
    assert!(rest.is_empty());
    let mut output = Vec::new();
    for (coset_index, positions) in groups.iter().enumerate() {
        if positions.is_empty() {
            continue;
        }
        for value in extension_values_selected(
            &coefficients,
            coset(coset_index),
            Transform::cached(SYSTEMATIC),
            positions,
        ) {
            output.extend(field::encode(value));
        }
    }
    output
}

fn first_coefficients(input: &[u8]) -> Vec<u8> {
    let width = usize::from(input[0]);
    assert!(width == 2 || width == 16);
    let (mask, values) = input[1..].split_at(MASKS * WORD_BYTES);
    assert_eq!(values.len(), SYSTEMATIC * width);
    let mask = Zeroizing::new(mask.chunks_exact(WORD_BYTES).map(word).collect::<Vec<_>>());
    let coefficients = if width == 2 {
        let words = Zeroizing::new(
            values
                .chunks_exact(2)
                .map(|value| u16::from_le_bytes(value.try_into().unwrap()))
                .collect::<Vec<_>>(),
        );
        masked_base_polynomial(BaseValues::Words(&words), &mask)
    } else {
        let counts = Zeroizing::new(
            values
                .chunks_exact(WORD_BYTES)
                .map(word)
                .collect::<Vec<_>>(),
        );
        masked_base_polynomial(BaseValues::Counts(&counts), &mask)
    };
    let mut output = Vec::with_capacity(WORD_BYTES * coefficients.len());
    for value in coefficients.iter() {
        output.extend(value.to_le_bytes());
    }
    output
}
fn second_coefficients(input: &[u8]) -> Vec<u8> {
    let (coefficients, rest) = decode_second(input);
    assert!(rest.is_empty());
    let mut output = Vec::with_capacity(ELEMENT_BYTES * coefficients.len());
    for value in coefficients.iter() {
        output.extend(field::encode(*value));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_column_inputs_have_their_exact_length() {
        let words = vec![u16::MAX; SYSTEMATIC];
        let counts = vec![u128::MAX; SYSTEMATIC];
        let base_mask = vec![u128::MAX; MASKS];
        let extension_mask = vec![[u128::MAX; 3]; MASKS];
        for column in [
            base_column(BaseValues::Words(&words), &base_mask),
            base_column(BaseValues::Counts(&counts), &base_mask),
            second_column(
                SecondValues::Lookup {
                    words: &words,
                    factor: 512,
                },
                &extension_mask,
            ),
            second_column(SecondValues::Counts(&counts), &extension_mask),
        ] {
            assert_eq!(column.capacity(), column.len());
        }
    }
}
