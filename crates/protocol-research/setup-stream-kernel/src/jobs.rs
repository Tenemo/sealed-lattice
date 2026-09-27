//! Query evaluations that helper instances of the participant module run
//! on their own. The owner checks each job's parameters with the
//! refusals of a direct evaluation before it submits the job, so a job's
//! output is a function of its input bytes.
use super::{Element, Error, ZERO, plus, query, setup};
use parallel_work::{Job, Part, Pipeline, Ticket, submit};

/// A geometry's sum and query values.
pub static GEOMETRY: Job = Job {
    kind: 0x0200,
    run: geometry,
};
/// Values' masked interpolant at queried positions.
pub static QUERIES: Job = Job {
    kind: 0x0201,
    run: queries,
};
pub static JOBS: [&Job; 2] = [&GEOMETRY, &QUERIES];

const ELEMENT_BYTES: usize = 48;

fn encode(value: Element, output: &mut Vec<u8>) {
    for coordinate in value {
        output.extend(coordinate.to_le_bytes());
    }
}
fn decode(bytes: &[u8]) -> Element {
    std::array::from_fn(|index| {
        u128::from_le_bytes(bytes[16 * index..16 * (index + 1)].try_into().unwrap())
    })
}
/// The elements of a job's output.
pub(crate) fn decode_values(output: &[u8]) -> Vec<Element> {
    output.chunks_exact(ELEMENT_BYTES).map(decode).collect()
}
fn number(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
// The systematic size and the queried indices, then the bytes after them.
fn push_queries(output: &mut Vec<u8>, indices: &[u32], systematic_size: usize) {
    output.extend((systematic_size as u32).to_le_bytes());
    output.extend((indices.len() as u32).to_le_bytes());
    for index in indices {
        output.extend(index.to_le_bytes());
    }
}
fn read_queries(input: &[u8]) -> (usize, Vec<u32>, &[u8]) {
    let systematic_size = number(input);
    let count = number(&input[4..]);
    let indices = input[8..8 + 4 * count]
        .chunks_exact(4)
        .map(|index| u32::from_le_bytes(index.try_into().unwrap()))
        .collect();
    (systematic_size, indices, &input[8 + 4 * count..])
}

/// Starts the evaluation of the values' masked interpolant at the indices,
/// after the refusals of a direct evaluation.
pub(crate) fn queries_job(
    values: &[Element],
    indices: &[u32],
    systematic_size: usize,
) -> Result<Ticket, Error> {
    query::check_in(values.len(), indices, systematic_size)?;
    let mut input = Vec::with_capacity(8 + 4 * indices.len() + ELEMENT_BYTES * values.len());
    push_queries(&mut input, indices, systematic_size);
    for value in values {
        encode(*value, &mut input);
    }
    Ok(submit(
        &QUERIES,
        None,
        &[Part::Bytes(&input)],
        ELEMENT_BYTES * indices.len(),
    ))
}
fn queries(input: &[u8]) -> Vec<u8> {
    let (systematic_size, indices, values) = read_queries(input);
    let values = decode_values(values);
    let mut output = Vec::with_capacity(ELEMENT_BYTES * indices.len());
    for value in query::evaluate_in(values, &indices, systematic_size).expect("Checked queries") {
        encode(value, &mut output);
    }
    output
}

/// Starts the evaluation of a geometry's sum and query values.
pub(crate) fn geometry_job(
    key: setup::GeometryKey,
    alpha: Element,
    indices: &[u32],
    systematic_size: usize,
) -> Result<Ticket, Error> {
    query::check_in(key.degree, indices, systematic_size)?;
    let mut input = Vec::new();
    for value in [key.degree, key.automorphism, key.shift] {
        input.extend((value as u32).to_le_bytes());
    }
    input.push(u8::from(key.constant));
    encode(alpha, &mut input);
    push_queries(&mut input, indices, systematic_size);
    Ok(submit(
        &GEOMETRY,
        None,
        &[Part::Bytes(&input)],
        ELEMENT_BYTES * (1 + indices.len()),
    ))
}
fn geometry(input: &[u8]) -> Vec<u8> {
    let key = setup::GeometryKey {
        degree: number(input),
        automorphism: number(&input[4..]),
        shift: number(&input[8..]),
        constant: input[12] == 1,
    };
    let alpha = decode(&input[13..13 + ELEMENT_BYTES]);
    let (systematic_size, indices, rest) = read_queries(&input[13 + ELEMENT_BYTES..]);
    assert!(rest.is_empty());
    let values = setup::geometry_values(key, alpha);
    let mut output = Vec::with_capacity(ELEMENT_BYTES * (1 + indices.len()));
    encode(values.iter().copied().fold(ZERO, plus), &mut output);
    for value in query::evaluate_in(values, &indices, systematic_size).expect("Checked geometry") {
        encode(value, &mut output);
    }
    output
}
/// A geometry job's sum and query values.
pub(crate) fn decode_geometry(output: &[u8]) -> (Element, Vec<Element>) {
    let values = decode_values(output);
    (values[0], values[1..].to_vec())
}

/// Each column's masked interpolant at the indices, in column order, with
/// the refusals of evaluating each column directly.
pub fn evaluate_public_columns(
    columns: Vec<Vec<Element>>,
    indices: &[u32],
) -> Result<Vec<Element>, Error> {
    let mut output = Vec::with_capacity(columns.len() * indices.len());
    let mut pipeline = Pipeline::new(parallel_work::window());
    for (index, column) in columns.into_iter().enumerate() {
        let ticket = queries_job(&column, indices, query::SYSTEMATIC_SIZE)?;
        if let Some((_, bytes)) = pipeline.push(index, ticket) {
            output.extend(decode_values(&bytes));
        }
    }
    for (_, bytes) in pipeline.finish() {
        output.extend(decode_values(&bytes));
    }
    Ok(output)
}
