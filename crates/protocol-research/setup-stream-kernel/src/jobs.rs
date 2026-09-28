//! Query evaluations and coefficient fingerprints that helper instances of
//! the participant module run on their own. The owner checks each job's
//! parameters with the refusals of a direct evaluation before it submits the
//! job, so a job's output is a function of its input bytes.
use super::{
    Element, Error, ZERO, adjoint_of, limb_powers, plus, power, query, record_fingerprint, setup,
    times,
};
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
/// A run of canonical coefficient records' fingerprints, weighted by the
/// powers of alpha from the run's position and summed, then with retention
/// each record's fingerprint.
pub static FINGERPRINTS: Job = Job {
    kind: 0x0202,
    run: fingerprints,
};
/// A polynomial's adjoint from its coefficients' fingerprints and their
/// weighted sum, at queried positions of its masked interpolant.
pub static ADJOINT: Job = Job {
    kind: 0x0203,
    run: adjoint,
};
pub static JOBS: [&Job; 4] = [&GEOMETRY, &QUERIES, &FINGERPRINTS, &ADJOINT];

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

/// Starts the fingerprints of a run of canonical records of width bytes,
/// from its position in a polynomial whose parameters were checked.
pub(crate) fn fingerprints_job(
    width: usize,
    radix_bits: usize,
    degree: usize,
    position: usize,
    retain: bool,
    alpha: Element,
    records: &[u8],
) -> Ticket {
    let count = records.len() / width;
    assert!(records.len() == count * width && position + count <= degree);
    let mut header = Vec::with_capacity(17 + ELEMENT_BYTES);
    for value in [width, radix_bits, degree, position] {
        header.extend((value as u32).to_le_bytes());
    }
    header.push(u8::from(retain));
    encode(alpha, &mut header);
    submit(
        &FINGERPRINTS,
        None,
        &[Part::Bytes(&header), Part::Bytes(records)],
        ELEMENT_BYTES * (1 + if retain { count } else { 0 }),
    )
}
fn fingerprints(input: &[u8]) -> Vec<u8> {
    let [width, radix_bits, degree, position] =
        std::array::from_fn(|index| number(&input[4 * index..]));
    let retain = input[16] == 1;
    let alpha = decode(&input[17..17 + ELEMENT_BYTES]);
    let records = &input[17 + ELEMENT_BYTES..];
    let powers = limb_powers(width - 1, radix_bits, power(alpha, degree));
    let mut weight = power(alpha, position);
    let mut sum = ZERO;
    let mut retained = Vec::new();
    for record in records.chunks_exact(width) {
        let value = record_fingerprint(record, radix_bits, &powers);
        sum = plus(sum, times(weight, value));
        weight = times(weight, alpha);
        if retain {
            encode(value, &mut retained);
        }
    }
    let mut output = Vec::with_capacity(ELEMENT_BYTES + retained.len());
    encode(sum, &mut output);
    output.extend(retained);
    output
}
/// A fingerprints job's weighted sum, then its retained fingerprints.
pub(crate) fn split_fingerprints(output: &[u8]) -> (Element, &[u8]) {
    (decode(output), &output[ELEMENT_BYTES..])
}

/// Starts the evaluation at the indices of the adjoint of the encoded
/// fingerprints whose weighted sum is the total, after the refusals of a
/// direct evaluation.
pub(crate) fn adjoint_job(
    fingerprints: &[u8],
    total: Element,
    alpha: Element,
    indices: &[u32],
    systematic_size: usize,
) -> Result<Ticket, Error> {
    query::check_in(fingerprints.len() / ELEMENT_BYTES, indices, systematic_size)?;
    let mut header = Vec::with_capacity(8 + 4 * indices.len() + 2 * ELEMENT_BYTES);
    push_queries(&mut header, indices, systematic_size);
    encode(total, &mut header);
    encode(alpha, &mut header);
    Ok(submit(
        &ADJOINT,
        None,
        &[Part::Bytes(&header), Part::Bytes(fingerprints)],
        1 + ELEMENT_BYTES * indices.len(),
    ))
}
fn adjoint(input: &[u8]) -> Vec<u8> {
    let (systematic_size, indices, rest) = read_queries(input);
    let total = decode(rest);
    let alpha = decode(&rest[ELEMENT_BYTES..]);
    let fingerprints = decode_values(&rest[2 * ELEMENT_BYTES..]);
    let limb_weight = power(alpha, fingerprints.len());
    let mut output = Vec::with_capacity(1 + ELEMENT_BYTES * indices.len());
    match adjoint_of(fingerprints, total, alpha, limb_weight) {
        Ok(values) => {
            output.push(0);
            for value in
                query::evaluate_in(values, &indices, systematic_size).expect("Checked queries")
            {
                encode(value, &mut output);
            }
        }
        Err(_) => output.resize(1 + ELEMENT_BYTES * indices.len(), 1),
    }
    output
}
/// An adjoint job's query values, refused when the adjoint does not close.
pub(crate) fn decode_adjoint(output: &[u8]) -> Result<Vec<Element>, Error> {
    match output[0] {
        0 => Ok(decode_values(&output[1..])),
        _ => Err(Error::Arithmetic),
    }
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
/// the refusals of evaluating each column directly. Without helpers, as in a
/// helper's own session, each column evaluates in place, as its job would
/// evaluate the column's decoded copy.
pub fn evaluate_public_columns(
    columns: Vec<Vec<Element>>,
    indices: &[u32],
) -> Result<Vec<Element>, Error> {
    let mut output = Vec::with_capacity(columns.len() * indices.len());
    if parallel_work::helpers() == 0 {
        for column in columns {
            output.extend(query::evaluate_in(column, indices, query::SYSTEMATIC_SIZE)?);
        }
        return Ok(output);
    }
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
