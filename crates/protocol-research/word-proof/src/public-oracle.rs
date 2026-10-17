//! A public coefficient oracle. Its deterministic, unsalted Merkle tree
//! can be reproduced from the published polynomials by any selector.
use crate::{
    field::{self, Element, Transform, ZERO, base},
    transcript::part,
};
use parallel_work::ProtocolHash;
use statement_stream::Refusal;
use std::collections::BTreeSet;
use supported_profile::relation::{EVALUATION_DOMAIN_SIZE, SYSTEMATIC};

const LEAF: &[u8] = b"committed-key/leaf";
const NODE: &[u8] = b"committed-key/node";

pub fn evaluate(coefficients: &[u128], point: Element) -> Element {
    coefficients.iter().rev().fold(ZERO, |sum, coefficient| {
        field::add(field::multiply(sum, point), [*coefficient, 0, 0])
    })
}

/// Adds the column and its evaluation quotient with their independent
/// degree-correction weights. The quotient is computed by synthetic division.
pub fn add_combination(
    combined: &mut [Element],
    coefficients: &[u128],
    point: Element,
    claimed: Element,
    weights: [Element; 4],
) -> Result<(), Refusal> {
    let degree = coefficients.len();
    if degree < 2 || combined.len() != 2 * degree || evaluate(coefficients, point) != claimed {
        return Err(Refusal::Parameters);
    }
    for (index, coefficient) in coefficients.iter().enumerate() {
        combined[index] = field::add(combined[index], field::scale(weights[0], *coefficient));
        combined[index + degree] = field::add(
            combined[index + degree],
            field::scale(weights[1], *coefficient),
        );
    }
    let mut quotient = ZERO;
    for index in (0..degree - 1).rev() {
        quotient = field::add(
            [coefficients[index + 1], 0, 0],
            field::multiply(point, quotient),
        );
        combined[index] = field::add(combined[index], field::multiply(weights[2], quotient));
        combined[index + degree + 1] = field::add(
            combined[index + degree + 1],
            field::multiply(weights[3], quotient),
        );
    }
    Ok(())
}

fn leaf(role: &[u8], index: usize, width: usize) -> ProtocolHash {
    let mut hash = ProtocolHash::new();
    part(&mut hash, LEAF);
    part(&mut hash, role);
    part(&mut hash, &(index as u32).to_le_bytes());
    hash.update((width as u32).to_le_bytes());
    hash
}

fn node(role: &[u8], level: usize, left: &[u8; 64], right: &[u8; 64]) -> [u8; 64] {
    let mut hash = ProtocolHash::new();
    part(&mut hash, NODE);
    part(&mut hash, role);
    part(&mut hash, &(level as u32).to_le_bytes());
    part(&mut hash, left);
    part(&mut hash, right);
    hash.finalize()
}

fn evaluations(coefficients: &[u128], domain: usize) -> Result<Vec<u128>, Refusal> {
    if coefficients.len() != domain / 4 || coefficients.iter().any(|value| *value >= field::MODULUS)
    {
        return Err(Refusal::Parameters);
    }
    let mut values = vec![0; domain];
    let mut power = 1;
    for (value, coefficient) in values.iter_mut().zip(coefficients) {
        *value = base::multiply(*coefficient, power);
        power = base::multiply(power, 7);
    }
    Transform::cached(domain / 4).base(&mut values, false);
    Ok(values)
}

pub struct PublicOracleBuilder {
    role: Vec<u8>,
    columns: usize,
    next: usize,
    rows: Vec<ProtocolHash>,
}

impl PublicOracleBuilder {
    pub fn new(role: &[u8], columns: usize) -> Result<Self, Refusal> {
        Self::with_domain(role, columns, EVALUATION_DOMAIN_SIZE)
    }

    fn with_domain(role: &[u8], columns: usize, domain: usize) -> Result<Self, Refusal> {
        if role.is_empty()
            || role.len() > 1024
            || columns == 0
            || columns > 4096
            || !domain.is_power_of_two()
            || !(8..=EVALUATION_DOMAIN_SIZE).contains(&domain)
        {
            return Err(Refusal::Parameters);
        }
        Ok(Self {
            role: role.to_vec(),
            columns,
            next: 0,
            rows: (0..domain)
                .map(|index| leaf(role, index, 16 * columns))
                .collect(),
        })
    }

    pub fn column(&mut self, coefficients: &[u128]) -> Result<(), Refusal> {
        if self.next == self.columns {
            return Err(Refusal::Parameters);
        }
        let values = evaluations(coefficients, self.rows.len())?;
        for (row, value) in self.rows.iter_mut().zip(values) {
            row.update(value.to_le_bytes());
        }
        self.next += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<PublicOracle, Refusal> {
        if self.next != self.columns {
            return Err(Refusal::Parameters);
        }
        let length = self.rows.len();
        let mut nodes = vec![[0; 64]; 2 * length];
        for (destination, hash) in nodes[length..].iter_mut().zip(self.rows) {
            *destination = hash.finalize();
        }
        let mut first = length / 2;
        let mut level = 1;
        while first != 0 {
            for index in first..2 * first {
                nodes[index] = node(&self.role, level, &nodes[2 * index], &nodes[2 * index + 1]);
            }
            first /= 2;
            level += 1;
        }
        Ok(PublicOracle {
            role: self.role,
            length,
            width: self.columns * 16,
            nodes,
        })
    }
}

pub struct PublicOracle {
    role: Vec<u8>,
    length: usize,
    width: usize,
    nodes: Vec<[u8; 64]>,
}

#[derive(Default)]
pub struct PublicMultiproof {
    known: BTreeSet<usize>,
}

impl PublicOracle {
    pub(crate) fn from_rows(role: &[u8], rows: &[Element]) -> Self {
        let length = rows.len();
        assert!(length.is_power_of_two() && (8..=EVALUATION_DOMAIN_SIZE).contains(&length));
        let mut nodes = vec![[0; 64]; 2 * length];
        for (index, row) in rows.iter().enumerate() {
            let mut hash = leaf(role, index, 48);
            hash.update(field::encode(*row));
            nodes[length + index] = hash.finalize();
        }
        let mut first = length / 2;
        let mut level = 1;
        while first != 0 {
            for index in first..2 * first {
                nodes[index] = node(role, level, &nodes[2 * index], &nodes[2 * index + 1]);
            }
            first /= 2;
            level += 1;
        }
        Self {
            role: role.to_vec(),
            length,
            width: 48,
            nodes,
        }
    }
    pub fn root(&self) -> [u8; 64] {
        self.nodes[1]
    }

    pub fn write_record(
        &self,
        proof: &mut PublicMultiproof,
        index: usize,
        row: &[u8],
        output: &mut Vec<u8>,
    ) -> Result<(), Refusal> {
        if index >= self.length || row.len() != self.width {
            return Err(Refusal::Parameters);
        }
        let mut hash = leaf(&self.role, index, self.width);
        hash.update(row);
        if hash.finalize() != self.nodes[self.length + index] {
            return Err(Refusal::Parameters);
        }
        output.extend((index as u32).to_le_bytes());
        output.extend_from_slice(row);
        let mut current = self.length + index;
        while current > 1 && !proof.known.contains(&current) {
            proof.known.insert(current);
            if proof.known.insert(current ^ 1) {
                output.extend(self.nodes[current ^ 1]);
            }
            current /= 2;
        }
        Ok(())
    }
}

/// Only the requested rows, filled a column at a time. Re-encoding the
/// public coefficients needs one transform and no expanded-oracle buffer.
pub struct PublicOpenings {
    indices: Vec<usize>,
    rows: Vec<Vec<u8>>,
    columns: usize,
    next: usize,
}

impl PublicOpenings {
    pub fn new(indices: &[usize], columns: usize) -> Result<Self, Refusal> {
        if columns == 0
            || columns > 4096
            || indices.is_empty()
            || indices.len() > EVALUATION_DOMAIN_SIZE
            || indices
                .last()
                .is_none_or(|index| *index >= EVALUATION_DOMAIN_SIZE)
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Refusal::Parameters);
        }
        Ok(Self {
            indices: indices.to_vec(),
            rows: indices
                .iter()
                .map(|_| Vec::with_capacity(16 * columns))
                .collect(),
            columns,
            next: 0,
        })
    }

    pub fn column(&mut self, coefficients: &[u128]) -> Result<(), Refusal> {
        if self.next == self.columns {
            return Err(Refusal::Parameters);
        }
        let values = evaluations(coefficients, 4 * SYSTEMATIC)?;
        for (index, row) in self.indices.iter().zip(&mut self.rows) {
            row.extend(values[*index].to_le_bytes());
        }
        self.next += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<(usize, Vec<u8>)>, Refusal> {
        if self.next != self.columns {
            return Err(Refusal::Parameters);
        }
        Ok(self.indices.into_iter().zip(self.rows).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_tree_matches_independent_direct_evaluations_and_paths() {
        let columns = [vec![0, 1, field::MODULUS - 2, 3], vec![7, 0, 11, 19]];
        let mut builder = PublicOracleBuilder::with_domain(b"offer", columns.len(), 16).unwrap();
        for column in &columns {
            builder.column(column).unwrap();
        }
        let oracle = builder.finish().unwrap();
        let mut direct: Vec<[u8; 64]> = (0..16)
            .map(|index| {
                let point = base::multiply(7, base::power(field::root(16), index));
                let mut hash = leaf(b"offer", index as usize, 32);
                for column in &columns {
                    let value = column.iter().rev().fold(0, |sum, coefficient| {
                        base::add(base::multiply(sum, point), *coefficient)
                    });
                    hash.update(value.to_le_bytes());
                }
                hash.finalize()
            })
            .collect();
        let mut level = 1;
        while direct.len() > 1 {
            direct = direct
                .chunks_exact(2)
                .map(|pair| node(b"offer", level, &pair[0], &pair[1]))
                .collect();
            level += 1;
        }
        assert_eq!(oracle.root(), direct[0]);
        let mut changed = PublicOracleBuilder::with_domain(b"another offer", 2, 16).unwrap();
        for column in &columns {
            changed.column(column).unwrap();
        }
        assert_ne!(oracle.root(), changed.finish().unwrap().root());
    }

    #[test]
    fn refuses_incomplete_columns_and_out_of_field_coefficients() {
        let mut builder = PublicOracleBuilder::with_domain(b"offer", 2, 16).unwrap();
        assert!(builder.column(&[0; 3]).is_err());
        assert!(builder.column(&[field::MODULUS; 4]).is_err());
        builder.column(&[0; 4]).unwrap();
        assert!(builder.finish().is_err());
        assert!(PublicOpenings::new(&[2, 1], 1).is_err());
        assert!(PublicOpenings::new(&[2, 2], 1).is_err());
        assert!(PublicOpenings::new(&[EVALUATION_DOMAIN_SIZE], 1).is_err());
    }
}
