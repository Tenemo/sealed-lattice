use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    jobs::{self, BaseValues, SecondValues},
    parameters::*,
    rows::RowShards,
    tree::Tree,
};
use parallel_work::{Job, Part, Pipeline, Shared, Ticket, share, submit};
use std::collections::VecDeque;
use zeroize::{Zeroize, Zeroizing};

pub fn random_base(count: usize) -> Vec<u128> {
    let mut output = Vec::with_capacity(count);
    let mut bytes = Zeroizing::new(vec![0; RANDOM_READ_BYTES]);
    while output.len() < count {
        crate::random::fill(&mut bytes);
        for word in bytes.chunks_exact(RANDOM_WORD_BYTES) {
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
    pub relation: Relation,
    pub statement: [u8; 64],
    pub columns: Vec<Vec<u16>>,
    pub counts: Vec<u128>,
}
impl Witness {
    pub fn from_columns(
        relation: &Relation,
        statement: [u8; 64],
        columns: Vec<Vec<u16>>,
    ) -> Result<Self, &'static str> {
        let mut columns = Zeroizing::new(columns);
        let words = relation.words();
        if columns.len() != relation.columns()
            || columns.iter().any(|column| column.len() != SYSTEMATIC)
        {
            return Err("Witness shape");
        }
        if columns[words..].iter().flatten().any(|value| *value > 1) {
            return Err("Boolean range");
        }
        let mut counts = vec![0; SYSTEMATIC];
        for pair in 0..relation.zero_products() {
            let (left, right) = relation.zero_product_columns(pair);
            if columns[left]
                .iter()
                .zip(&columns[right])
                .any(|(left, right)| *left != 0 && *right != 0)
            {
                return Err("Nonzero product");
            }
        }
        for pair in 0..relation.support_pairs() {
            let (positive, negative) = relation.zero_product_columns(pair);
            let (positive, negative) = (&columns[positive], &columns[negative]);
            let (stride, required) = relation.support(pair);
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
        for index in 0..relation.lookups() {
            let (column, scale) = relation.lookup(index);
            for value in &columns[column] {
                let value = usize::from(*value) * scale as usize;
                if value >= SYSTEMATIC {
                    return Err("Narrow range");
                }
                counts[value] += 1;
            }
        }
        Ok(Self {
            relation: relation.clone(),
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
    // The leaf hashers until the commitment finishes.
    pub(crate) rows: Option<RowShards>,
    // The coefficient jobs of the next columns, in column order.
    pub(crate) prefetched: VecDeque<(usize, Ticket)>,
}

pub struct SecondOracle {
    pub masks: Vec<Vec<Element>>,
    pub sum_mask: Vec<Element>,
    pub mask_sum: Element,
    pub lookup_coefficients: Vec<Element>,
    pub tree: Tree,
    rows: Option<RowShards>,
    prefetched: VecDeque<(usize, Ticket)>,
    // The reciprocal table that the column jobs read.
    table: Option<Shared>,
}

// Starts the coefficient jobs of the columns after the next committed one
// that a helper may run ahead, and returns the next column's job. Jobs of
// other columns are abandoned.
fn next_coefficients(
    prefetched: &mut VecDeque<(usize, Ticket)>,
    column: usize,
    last: usize,
    mut start: impl FnMut(usize) -> Ticket,
) -> Ticket {
    if prefetched
        .front()
        .is_some_and(|(index, _)| *index != column)
    {
        prefetched.clear();
    }
    let mut next = prefetched.back().map_or(column, |(index, _)| index + 1);
    while next <= last.min(column + parallel_work::helpers()) {
        prefetched.push_back((next, start(next)));
        next += 1;
    }
    prefetched.pop_front().unwrap().1
}
// A column's coefficient job on its input parts.
fn coefficient_job(job: &'static Job, parts: &[Part], width: usize) -> Ticket {
    submit(job, None, parts, jobs::coefficient_bytes(width))
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

/// The coefficients of a base column's masked polynomial: its interpolant
/// less the mask, then the mask times the systematic power.
pub(crate) fn masked_base_polynomial(values: BaseValues, mask: &[u128]) -> Zeroizing<Vec<u128>> {
    let mut coefficients = Zeroizing::new(Vec::with_capacity(SYSTEMATIC + mask.len()));
    match values {
        BaseValues::Words(values) => {
            coefficients.extend(values.iter().map(|value| u128::from(*value)))
        }
        BaseValues::Counts(values) => coefficients.extend_from_slice(values),
    }
    Transform::cached(SYSTEMATIC).base(&mut coefficients, true);
    for (coefficient, value) in coefficients.iter_mut().zip(mask) {
        *coefficient = base::subtract(*coefficient, *value);
    }
    coefficients.extend_from_slice(mask);
    coefficients
}
/// The coefficients of an extension column's masked polynomial: its
/// interpolant less the mask, then the mask times the systematic power.
pub(crate) fn masked_extension_coefficients(
    values: impl Iterator<Item = Element>,
    mask: &[Element],
    transform: &Transform,
) -> Vec<Element> {
    let mut coefficients = Zeroizing::new(Vec::with_capacity(SYSTEMATIC + mask.len()));
    coefficients.extend(values);
    transform.extension(&mut coefficients, true);
    for (coefficient, value) in coefficients.iter_mut().zip(mask) {
        *coefficient = field::subtract(*coefficient, *value);
    }
    coefficients.extend_from_slice(mask);
    std::mem::take(&mut *coefficients)
}

impl SecondOracle {
    pub fn create(role: &[u8], witness: &Witness, inverses: &[Element]) -> Self {
        assert_eq!(inverses.len(), SYSTEMATIC);
        let mut result = Self::initialize(&witness.relation, role);
        for column in 0..witness.relation.lookups() + 2 {
            result.commit_column(witness, inverses, column);
        }
        result.finish_commitment();
        result
    }
    pub fn initialize(relation: &Relation, role: &[u8]) -> Self {
        let masks = (0..relation.lookups() + 1)
            .map(|_| random_extension(MASKS))
            .collect();
        let sum_mask = random_extension(WITNESS_DEGREE + 1);
        let mask_sum = field::scale(
            field::add(sum_mask[0], sum_mask[SYSTEMATIC]),
            SYSTEMATIC as u128,
        );
        let tree = Tree::new(role, 1, DOMAIN, relation.second_width());
        let rows = Some(RowShards::open(&tree));
        Self {
            masks,
            sum_mask,
            mask_sum,
            lookup_coefficients: vec![ZERO; WITNESS_DEGREE + 1],
            tree,
            rows,
            prefetched: VecDeque::new(),
            table: None,
        }
    }
    // A committed column's values: a lookup's scaled words, whose
    // reciprocals it holds, or the multiplicities, which scale the table
    // reciprocals.
    fn column_values(witness: &Witness, column: usize) -> SecondValues<'_> {
        if column == witness.relation.lookups() {
            SecondValues::Counts(&witness.counts)
        } else {
            let (index, factor) = witness.relation.lookup(column);
            SecondValues::Lookup {
                words: &witness.columns[index],
                factor,
            }
        }
    }
    pub fn commit_column(&mut self, witness: &Witness, inverses: &[Element], column: usize) {
        let lookups = witness.relation.lookups();
        assert!(column < lookups + 2 && inverses.len() == SYSTEMATIC);
        if column == lookups + 1 {
            self.prefetched.clear();
            self.rows.as_mut().unwrap().absorb_extension(&self.sum_mask);
            return;
        }
        let table = self
            .table
            .get_or_insert_with(|| share(jobs::reciprocal_table(inverses)));
        let masks = &self.masks;
        let ticket = next_coefficients(&mut self.prefetched, column, lookups, |next| {
            let input = jobs::second_column(Self::column_values(witness, next), &masks[next]);
            coefficient_job(
                &jobs::SECOND_COEFFICIENTS,
                &[Part::Bytes(&input), Part::Shared(table)],
                48,
            )
        });
        let coefficients = ticket.wait();
        for (sum, value) in self
            .lookup_coefficients
            .iter_mut()
            .zip(coefficients.chunks_exact(48))
        {
            let value = field::decode(value);
            *sum = if column == lookups {
                field::subtract(*sum, value)
            } else {
                field::add(*sum, value)
            };
        }
        self.rows
            .as_mut()
            .unwrap()
            .absorb_extension_encoded(coefficients);
    }
    pub fn finish_commitment(&mut self) {
        self.rows.take().unwrap().close(&mut self.tree);
    }
    /// The oracle's rows at the leaves, in their order.
    pub fn opened_rows(
        &self,
        witness: &Witness,
        inverses: &[Element],
        indices: &[usize],
    ) -> Vec<Vec<u8>> {
        let transform = Transform::cached(SYSTEMATIC);
        let lookups = witness.relation.lookups();
        let mut data = vec![Vec::with_capacity(witness.relation.second_width()); indices.len()];
        let groups = query_groups(indices);
        let positions = jobs::positions(&groups);
        let mut consume = |output: Zeroizing<Vec<u8>>| {
            let mut values = output.chunks_exact(48);
            for selected in &groups {
                for (index, _) in selected {
                    data[*index].extend(values.next().unwrap());
                }
            }
            assert!(values.next().is_none());
        };
        let local;
        let table = match &self.table {
            Some(table) => table,
            None => {
                local = share(jobs::reciprocal_table(inverses));
                &local
            }
        };
        let mut pipeline = Pipeline::new(parallel_work::window());
        for column in 0..lookups + 1 {
            let input =
                jobs::second_column(Self::column_values(witness, column), &self.masks[column]);
            let ticket = submit(
                &jobs::SECOND_OPENINGS,
                None,
                &[
                    Part::Bytes(&positions),
                    Part::Bytes(&input),
                    Part::Shared(table),
                ],
                48 * indices.len(),
            );
            if let Some((_, output)) = pipeline.push(column, ticket) {
                consume(output);
            }
        }
        for (_, output) in pipeline.finish() {
            consume(output);
        }
        for (coset_index, selected) in groups.iter().enumerate() {
            if selected.is_empty() {
                continue;
            }
            let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
            let values = extension_values_selected(
                &self.sum_mask,
                coset(coset_index),
                transform,
                &positions,
            );
            for ((output, _), value) in selected.iter().zip(values) {
                data[*output].extend(field::encode(value));
            }
        }
        data
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
    // Only the coefficients above the systematic length wrap onto lower
    // ones, and a position without a coefficient stays zero.
    let wrapped = coefficients
        .len()
        .saturating_sub(SYSTEMATIC)
        .min(SYSTEMATIC);
    for (index, (value, coefficient)) in values.iter_mut().zip(coefficients).enumerate() {
        let folded = if index < wrapped {
            field::add(
                *coefficient,
                field::scale(coefficients[SYSTEMATIC + index], high),
            )
        } else {
            *coefficient
        };
        *value = field::scale(folded, power);
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
        let mut result = Self::initialize(&witness.relation, role, excess_degree);
        for column in 0..witness.relation.columns() + 2 {
            result.commit_column(witness, column);
        }
        result.finish_commitment();
        result
    }
    pub fn initialize(relation: &Relation, role: &[u8], excess_degree: bool) -> Self {
        let masks = (0..relation.columns() + 1)
            .map(|_| random_base(MASKS))
            .collect();
        let mut degree_mask = random_extension(MAX_DEGREE + 1);
        if excess_degree {
            degree_mask.push(field::ONE);
        }
        let tree = Tree::new(role, 0, DOMAIN, relation.first_width());
        let rows = Some(RowShards::open(&tree));
        Self {
            masks,
            degree_mask,
            tree,
            rows,
            prefetched: VecDeque::new(),
        }
    }
    // A committed base column's values: a witness column, or the lookup
    // multiplicities.
    fn column_values(witness: &Witness, column: usize) -> BaseValues<'_> {
        if column == witness.relation.columns() {
            BaseValues::Counts(&witness.counts)
        } else {
            BaseValues::Words(&witness.columns[column])
        }
    }
    pub fn commit_column(&mut self, witness: &Witness, column: usize) {
        let columns = witness.relation.columns();
        assert!(column < columns + 2);
        if column > columns {
            self.prefetched.clear();
            self.rows
                .as_mut()
                .unwrap()
                .absorb_extension(&self.degree_mask);
            return;
        }
        let masks = &self.masks;
        let ticket = next_coefficients(&mut self.prefetched, column, columns, |next| {
            let input = jobs::base_column(Self::column_values(witness, next), &masks[next]);
            coefficient_job(&jobs::FIRST_COEFFICIENTS, &[Part::Bytes(&input)], 16)
        });
        self.rows
            .as_mut()
            .unwrap()
            .absorb_base_encoded(ticket.wait());
    }
    pub fn finish_commitment(&mut self) {
        self.rows.take().unwrap().close(&mut self.tree);
    }
    /// The oracle's rows at the leaves, in their order.
    pub fn opened_rows(&self, witness: &Witness, indices: &[usize]) -> Vec<Vec<u8>> {
        let columns = witness.relation.columns();
        let mut data = vec![Vec::with_capacity(witness.relation.first_width()); indices.len()];
        let transform = Transform::cached(SYSTEMATIC);
        let groups = query_groups(indices);
        let positions = jobs::positions(&groups);
        let mut consume = |output: Zeroizing<Vec<u8>>| {
            let mut values = output.chunks_exact(16);
            for selected in &groups {
                for (index, _) in selected {
                    data[*index].extend(values.next().unwrap());
                }
            }
            assert!(values.next().is_none());
        };
        let mut pipeline = Pipeline::new(parallel_work::window());
        for column in 0..columns + 1 {
            let input =
                jobs::base_column(Self::column_values(witness, column), &self.masks[column]);
            let ticket = submit(
                &jobs::FIRST_OPENINGS,
                None,
                &[Part::Bytes(&positions), Part::Bytes(&input)],
                16 * indices.len(),
            );
            if let Some((_, output)) = pipeline.push(column, ticket) {
                consume(output);
            }
        }
        for (_, output) in pipeline.finish() {
            consume(output);
        }
        for (coset_index, selected) in groups.iter().enumerate() {
            if selected.is_empty() {
                continue;
            }
            let positions: Vec<_> = selected.iter().map(|(_, position)| *position).collect();
            let values = extension_values_selected(
                &self.degree_mask,
                coset(coset_index),
                transform,
                &positions,
            );
            for ((output, _), value) in selected.iter().zip(values) {
                data[*output].extend(field::encode(value));
            }
        }
        data
    }
}
