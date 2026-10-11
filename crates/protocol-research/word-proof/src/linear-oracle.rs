use crate::{
    field::{self, Element, MODULUS, ONE, Transform, ZERO, base},
    rows::{self, RowShards},
    sums::{self, ShardSums},
    tree::Tree,
};
use parallel_work::{Job, Part, Shared, Ticket, share, submit};
use std::collections::VecDeque;
use supported_profile::relation::*;
use zeroize::{Zeroize, Zeroizing};

// The jobs of the masked affine sum's values on the domain. A product's
// weighted public polynomial and its combination of committed columns are
// each computed once; then each shard of the domain's rows adds its values
// of the product, or of a weighted extension polynomial, to its sums where
// its jobs run. Each weight is the mask challenge, possibly times a public
// factor, so the finished sums are the values the oracle interpolates.

/// Adds a weighted extension polynomial's values at a shard's rows.
pub static TERM: Job = Job {
    kind: 0x0140,
    run: add_term,
};
/// The masked coefficients of a weighted combination of committed columns.
pub static COMBINATION: Job = Job {
    kind: 0x0141,
    run: combination,
};
/// Adds the products of a public polynomial with a combination of committed
/// columns at a shard's rows.
pub static PRODUCT: Job = Job {
    kind: 0x0142,
    run: add_product,
};
/// A weighted public polynomial's coefficients, which repeat with the
/// period of its values: a challenge's geometric sequence or adjoint
/// values, interpolated.
pub static PUBLIC: Job = Job {
    kind: 0x0143,
    run: public_coefficients,
};

const ELEMENT_BYTES: usize = 48;
const WORD_BYTES: usize = 16;
/// The residue classes of each coset's rows that the shards hold.
const CLASSES: usize = 2;
/// The shards of the domain's rows, one for each residue class of each
/// coset.
const SHARDS: usize = 4 * CLASSES;
const SHARD_ROWS: usize = SYSTEMATIC / CLASSES;
// A combined column's weight, mask and words in a combination job.
const COMBINED_COLUMN_BYTES: usize = ELEMENT_BYTES + WORD_BYTES * MASKS + 2 * SYSTEMATIC;
/// The most bytes of columns one combination job reads, which bounds its
/// memory beside its values and output.
const COMBINATION_INPUT_BYTES: usize = 4 << 20;
/// The products whose public polynomial and combinations run before their
/// shards' jobs start.
const PREPARED: usize = 2;

fn number(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize
}
fn word(bytes: &[u8]) -> u128 {
    u128::from_le_bytes(bytes[..WORD_BYTES].try_into().unwrap())
}
fn encoded(values: &[Element]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(ELEMENT_BYTES * values.len()));
    for value in values {
        bytes.extend(field::encode(*value));
    }
    bytes
}

fn add_term(input: &[u8]) -> Vec<u8> {
    let (session, shard, length, rest) = sums::header(input);
    assert_eq!(length, SHARD_ROWS);
    let (weight, coefficients) = rest.split_at(ELEMENT_BYTES);
    let weight = field::decode(weight);
    let values = rows::shard_extension_values(coefficients, shard, CLASSES);
    sums::with(session, shard, length, |sums| {
        for (sum, value) in sums.iter_mut().zip(values.iter()) {
            *sum = field::add(*sum, field::multiply(weight, *value));
        }
    });
    Vec::new()
}

fn combination(input: &[u8]) -> Vec<u8> {
    let count = number(input);
    let columns = &input[4..];
    assert_eq!(columns.len(), COMBINED_COLUMN_BYTES * count);
    let coefficients = Zeroizing::new(combined(columns, Transform::cached(SYSTEMATIC)));
    let mut output = Vec::with_capacity(ELEMENT_BYTES * coefficients.len());
    for coefficient in coefficients.iter() {
        output.extend(field::encode(*coefficient));
    }
    output
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

fn add_product(input: &[u8]) -> Vec<u8> {
    let (session, shard, length, rest) = sums::header(input);
    assert_eq!(length, SHARD_ROWS);
    let degree = number(rest);
    assert!(degree.is_power_of_two() && degree <= SYSTEMATIC);
    let (public, combination) = rest[4..].split_at(ELEMENT_BYTES * degree);
    assert_eq!(combination.len(), ELEMENT_BYTES * (WITNESS_DEGREE + 1));
    let public = rows::shard_extension_values_of(
        SYSTEMATIC,
        |index| field::decode(&public[ELEMENT_BYTES * (index % degree)..]),
        shard,
        CLASSES,
    );
    let combination = rows::shard_extension_values(combination, shard, CLASSES);
    sums::with(session, shard, length, |sums| {
        for ((sum, public), combination) in
            sums.iter_mut().zip(public.iter()).zip(combination.iter())
        {
            *sum = field::add(*sum, field::multiply(*public, *combination));
        }
    });
    Vec::new()
}

fn public_coefficients(input: &[u8]) -> Vec<u8> {
    let (weight, rest) = input.split_at(ELEMENT_BYTES);
    let weight = field::decode(weight);
    let values = match rest[0] {
        0 => {
            let alpha = field::decode(&rest[1..1 + ELEMENT_BYTES]);
            let rest = &rest[1 + ELEMENT_BYTES..];
            assert_eq!(rest.len(), 13);
            let constant = match rest[12] {
                0 => false,
                1 => true,
                _ => panic!("Geometric constant"),
            };
            geometric(
                alpha,
                number(rest),
                number(&rest[4..]),
                number(&rest[8..]),
                constant,
            )
        }
        1 => {
            let count = number(&rest[1..]);
            let values = &rest[5..];
            assert_eq!(values.len(), ELEMENT_BYTES * count);
            values
                .chunks_exact(ELEMENT_BYTES)
                .map(field::decode)
                .collect()
        }
        _ => panic!("Public polynomial"),
    };
    std::mem::take(&mut *encoded(&interpolated(values, weight)))
}
// The weighted coefficients of the polynomial whose values on the
// systematic domain are the values at every stride-th row and zero between
// them. They repeat with the values' period, so one period represents
// them.
fn interpolated(mut values: Vec<Element>, weight: Element) -> Vec<Element> {
    let degree = values.len();
    assert!(degree.is_power_of_two() && degree <= SYSTEMATIC);
    if degree > 1 {
        Transform::cached(SYSTEMATIC).extension(&mut values, true);
    }
    let stride = SYSTEMATIC / degree;
    let factor = field::scale(weight, base::power(stride as u128, MODULUS - 2));
    for value in values.iter_mut() {
        *value = field::multiply(*value, factor);
    }
    values
}
fn geometric(
    alpha: Element,
    degree: usize,
    automorphism: usize,
    shift: usize,
    constant: bool,
) -> Vec<Element> {
    assert!(degree.is_power_of_two() && degree <= SYSTEMATIC);
    if constant {
        return vec![ONE; degree];
    }
    let mut powers = Vec::with_capacity(degree);
    let mut current = ONE;
    for _ in 0..degree {
        powers.push(current);
        current = field::multiply(current, alpha);
    }
    (0..degree)
        .map(|index| {
            let exponent = (index * automorphism + shift) % (2 * degree);
            if exponent < degree {
                powers[exponent % degree]
            } else {
                field::subtract(ZERO, powers[exponent % degree])
            }
        })
        .collect()
}

/// A product's public polynomial: a challenge's geometric sequence, or
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
// A product whose public polynomial's and combinations' jobs run: the sum
// of its ended combinations and the count still running.
struct Prepared {
    degree: usize,
    public: Ticket,
    combination: Option<Zeroizing<Vec<u8>>>,
    running: usize,
}
/// The masked affine sum's values on the domain, which the jobs of its
/// terms add in the shards of the domain's rows.
pub struct AffineValues {
    sums: ShardSums,
    // Products whose shards' jobs have yet to start, oldest first.
    prepared: VecDeque<Prepared>,
    // The running combinations, oldest first, each with its product's
    // position among the prepared products that have ever started.
    combinations: VecDeque<(usize, Ticket)>,
    // The products that have left the prepared ones.
    started: usize,
}
impl Default for AffineValues {
    fn default() -> Self {
        Self::new()
    }
}
impl AffineValues {
    pub fn new() -> Self {
        Self {
            sums: ShardSums::new(SHARDS, SHARD_ROWS),
            prepared: VecDeque::new(),
            combinations: VecDeque::new(),
            started: 0,
        }
    }
    // Adds the oldest running combination into its product's sum.
    fn end_combination(&mut self) {
        let (product, ticket) = self.combinations.pop_front().unwrap();
        let output = ticket.wait();
        let index = product - self.started;
        let prepared = &mut self.prepared[index];
        prepared.running -= 1;
        if let Some(sum) = &mut prepared.combination {
            for (sum, value) in sum
                .chunks_exact_mut(ELEMENT_BYTES)
                .zip(output.chunks_exact(ELEMENT_BYTES))
            {
                let total = field::add(field::decode(sum), field::decode(value));
                sum.copy_from_slice(&field::encode(total));
            }
        } else {
            prepared.combination = Some(output);
        }
    }
    /// Starts the jobs that add the products of the weighted public
    /// polynomial with the combination of the weighted committed columns of
    /// the words and masks: its coefficients' and the combination's jobs,
    /// each combining as many columns as its input bound allows, with at most
    /// one combination running for each helper, and once those of later
    /// products have started, the shards' jobs.
    pub fn products(
        &mut self,
        weight: Element,
        public: Public,
        columns: &[(usize, Element)],
        words: &[Vec<u16>],
        masks: &[Vec<u128>],
    ) {
        assert!(!columns.is_empty());
        let mut prefix = Vec::with_capacity(2 * ELEMENT_BYTES + 14);
        prefix.extend(field::encode(weight));
        let (degree, public) = match public {
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
                let parts = [Part::Bytes(&prefix)];
                (
                    degree,
                    submit(&PUBLIC, None, &parts, ELEMENT_BYTES * degree),
                )
            }
            Public::Adjoint { values, count } => {
                prefix.push(1);
                prefix.extend((count as u32).to_le_bytes());
                let parts = [Part::Bytes(&prefix), Part::Shared(values)];
                (count, submit(&PUBLIC, None, &parts, ELEMENT_BYTES * count))
            }
        };
        assert!(degree.is_power_of_two() && degree <= SYSTEMATIC);
        let product = self.started + self.prepared.len();
        self.prepared.push_back(Prepared {
            degree,
            public,
            combination: None,
            running: 0,
        });
        for chunk in columns.chunks(COMBINATION_INPUT_BYTES / COMBINED_COLUMN_BYTES) {
            while self.combinations.len() >= parallel_work::helpers().max(1) {
                self.end_combination();
            }
            let mut bytes =
                Zeroizing::new(Vec::with_capacity(4 + COMBINED_COLUMN_BYTES * chunk.len()));
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
            let ticket = submit(
                &COMBINATION,
                None,
                &[Part::Bytes(&bytes)],
                ELEMENT_BYTES * (WITNESS_DEGREE + 1),
            );
            self.combinations.push_back((product, ticket));
            self.prepared.back_mut().unwrap().running += 1;
        }
        while self.prepared.len() > PREPARED {
            self.start_oldest();
        }
    }
    // Starts the shards' jobs of the oldest prepared product on its public
    // polynomial's coefficients and the sum of its combinations, whose
    // combinations run before any later product's.
    fn start_oldest(&mut self) {
        while self.prepared[0].running > 0 {
            self.end_combination();
        }
        let Prepared {
            degree,
            public,
            combination,
            ..
        } = self.prepared.pop_front().unwrap();
        self.started += 1;
        let public = share(public.wait());
        let combination = share(combination.unwrap());
        let prefix = (degree as u32).to_le_bytes();
        for shard in 0..SHARDS {
            self.sums.submit(
                &PRODUCT,
                shard,
                &[
                    Part::Bytes(&prefix),
                    Part::Shared(&public),
                    Part::Shared(&combination),
                ],
            );
        }
    }
    /// Starts the jobs that add the weighted values of the coefficients.
    pub fn term(&mut self, weight: Element, coefficients: &[Element]) {
        assert!(coefficients.len() <= 2 * SYSTEMATIC + 1);
        let coefficients = share(encoded(coefficients));
        let weight = field::encode(weight);
        for shard in 0..SHARDS {
            self.sums.submit(
                &TERM,
                shard,
                &[Part::Bytes(&weight), Part::Shared(&coefficients)],
            );
        }
    }
    /// The values on the domain once every term's jobs have ended.
    pub fn finish(mut self) -> Zeroizing<Vec<Element>> {
        while !self.prepared.is_empty() {
            self.start_oldest();
        }
        let mut values = Zeroizing::new(vec![ZERO; EVALUATION_DOMAIN_SIZE]);
        self.sums.finish(|shard, first, output| {
            for (row, value) in output.chunks_exact(ELEMENT_BYTES).enumerate() {
                values[shard + SHARDS * (first + row)] = field::decode(value);
            }
        });
        values
    }
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
        assert_eq!(evaluations.len(), EVALUATION_DOMAIN_SIZE);
        Transform::cached(SYSTEMATIC).extension(&mut evaluations, true);
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
        let mut tree = Tree::new(role, 2, EVALUATION_DOMAIN_SIZE, 48);
        // Openings compute the quotient's values again.
        tree.forget_leaves();
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
    /// The oracle's encoded values at the leaves, in their order. Only
    /// the values an opening reveals leave it, so the values are zeroized.
    pub fn opened_rows(&self, indices: &[usize]) -> Vec<Vec<u8>> {
        let transform = Transform::cached(SYSTEMATIC);
        let mut data = Zeroizing::new(vec![ZERO; indices.len()]);
        for coset in 0..4 {
            let selected: Vec<_> = indices
                .iter()
                .enumerate()
                .filter(|(_, index)| **index % 4 == coset)
                .collect();
            if selected.is_empty() {
                continue;
            }
            let twist = base::multiply(
                7,
                base::power(field::root(EVALUATION_DOMAIN_SIZE), coset as u128),
            );
            let positions: Vec<_> = selected.iter().map(|(_, index)| **index / 4).collect();
            let values = Zeroizing::new(crate::oracles::extension_values_selected(
                &self.quotient,
                twist,
                transform,
                &positions,
            ));
            for ((output, _), value) in selected.into_iter().zip(values.iter()) {
                data[output] = *value;
            }
        }
        data.iter()
            .map(|value| field::encode(*value).to_vec())
            .collect()
    }
}
