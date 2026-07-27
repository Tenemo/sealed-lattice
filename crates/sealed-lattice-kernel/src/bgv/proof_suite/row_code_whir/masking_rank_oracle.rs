//! Independent hostile-domain masking oracle for the bound-reduction column.
//!
//! This module deliberately does not call production field, quotient, DFT,
//! sumcheck, or WHIR helpers. It follows the production chronology over a
//! smaller two-adic field and compares the complete affine witness image with
//! the joint persistent-material and proposed proof-pad image after every
//! revealed scalar.

use crate::bgv::proof_suite::{
    ValidatedRelationPlanArtifact, compile_same_secret_relation_plan,
    selected_committed_material_relation_plan_input, selected_relation_plan_check_context,
    selected_same_secret_relation_plan_input,
};
use crate::foundation::ProofApplicationSlotCeilings;

use super::construction_plan::RowCodeWhirConstructionPlan;

const HOSTILE_FIELD_MODULUS: u64 = 786_433;
const HOSTILE_FIELD_GENERATOR: u64 = 10;
const HOSTILE_VARIABLE_COUNT: usize = 12;
const HOSTILE_COEFFICIENT_COUNT: usize = 1 << HOSTILE_VARIABLE_COUNT;
const HOSTILE_INITIAL_FOLDING_FACTOR: usize = 3;
const HOSTILE_BOUND_VARIABLE_COUNT: usize = 8;
const HOSTILE_BOUND_COEFFICIENT_COUNT: usize = 1 << HOSTILE_BOUND_VARIABLE_COUNT;
const HOSTILE_TRACE_DOMAIN_SIZE: usize = HOSTILE_BOUND_COEFFICIENT_COUNT / 2;
const HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE: usize = 192;
const HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE: usize = HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE - 1;
const HOSTILE_WITNESS_COEFFICIENT_COUNT: usize = HOSTILE_TRACE_DOMAIN_SIZE;
const HOSTILE_PERSISTENT_MASK_COEFFICIENT_COUNT: usize =
    HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE - HOSTILE_TRACE_DOMAIN_SIZE;
const HOSTILE_CONTINUATION_PAD_START: usize = HOSTILE_COEFFICIENT_COUNT / 2;
const HOSTILE_CONTINUATION_PAD_COEFFICIENT_COUNT: usize =
    HOSTILE_COEFFICIENT_COUNT - HOSTILE_CONTINUATION_PAD_START;
const HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_ORDINAL: usize = 2;
const HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START: usize =
    HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_ORDINAL * HOSTILE_BOUND_COEFFICIENT_COUNT;
const HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_END: usize =
    HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START + HOSTILE_BOUND_COEFFICIENT_COUNT;
const HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOTS_START: usize =
    HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START;
const HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOT_COEFFICIENT_COUNT: usize =
    HOSTILE_COEFFICIENT_COUNT - HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOTS_START;
const HOSTILE_BOUND_LEAF_COUNT: usize = HOSTILE_BOUND_COEFFICIENT_COUNT / 2;
const HOSTILE_BOUND_QUERY_COUNT: usize = 2;
const HOSTILE_WHIR_QUERY_COUNT: usize = 4;
const HOSTILE_ROUND_COUNT: usize = 2;
const HOSTILE_FINAL_SUMCHECK_ROUND_COUNT: usize = 3;
const HOSTILE_SOURCE_OPENING_POINT: u64 = 107;
const HOSTILE_BOUND_QUERY_LEAF_INDICES: [usize; HOSTILE_BOUND_QUERY_COUNT] = [1, 17];
const HOSTILE_INITIAL_FOLD_CHALLENGES: [u64; HOSTILE_INITIAL_FOLDING_FACTOR] = [7, 19, 29];
const HOSTILE_ROUND_FOLD_CHALLENGES: [[u64; HOSTILE_INITIAL_FOLDING_FACTOR]; HOSTILE_ROUND_COUNT] =
    [[31, 37, 43], [71, 73, 79]];
const HOSTILE_ROUND_COMBINATION_CHALLENGES: [u64; HOSTILE_ROUND_COUNT] = [47, 67];
const HOSTILE_FINAL_FOLD_CHALLENGES: [u64; HOSTILE_FINAL_SUMCHECK_ROUND_COUNT] = [83, 89, 97];
const HOSTILE_QUERY_INDICES: [[usize; HOSTILE_WHIR_QUERY_COUNT]; HOSTILE_ROUND_COUNT + 1] =
    [[1, 6, 11, 16], [2, 9, 16, 23], [3, 14, 25, 36]];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostileSumcheckCoefficient {
    Constant,
    Quadratic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostileView {
    SourceOpening,
    BoundLeafValue {
        query_ordinal: usize,
        opposite: bool,
    },
    InitialSumcheck {
        round_ordinal: usize,
        coefficient: HostileSumcheckCoefficient,
    },
    WhirQuery {
        epoch_ordinal: usize,
        query_ordinal: usize,
        leaf_value_ordinal: usize,
    },
    RoundSumcheck {
        round_ordinal: usize,
        sumcheck_round_ordinal: usize,
        coefficient: HostileSumcheckCoefficient,
    },
    FinalCoefficient {
        coefficient_ordinal: usize,
    },
    FinalQuery {
        query_ordinal: usize,
        leaf_value_ordinal: usize,
    },
    FinalSumcheck {
        round_ordinal: usize,
        coefficient: HostileSumcheckCoefficient,
    },
}

#[derive(Clone, Debug)]
enum HostileFunctional {
    Source(Vec<u64>),
    Quotient(Vec<u64>),
}

#[derive(Clone, Debug)]
struct HostileAffineView {
    identifier: HostileView,
    functional: HostileFunctional,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostileDeficiency {
    identifier: HostileView,
    observation_ordinal: usize,
    mask_rank: usize,
    joint_rank: usize,
    first_uncovered_witness_coefficient_ordinal: usize,
}

#[derive(Clone, Debug)]
struct HostileOracleResult {
    first_deficiency: Option<HostileDeficiency>,
    final_mask_rank: usize,
    final_joint_rank: usize,
}

#[derive(Clone, Copy, Debug)]
enum HostileAdditionalMask {
    None,
    SelectorContinuation,
    UnusedBoundSelectorSlot,
    AllUnusedBoundSelectorSlots,
    RegisteredOpeningKernel,
}

impl HostileAdditionalMask {
    fn column_count(&self) -> usize {
        match self {
            Self::None => 0,
            Self::SelectorContinuation => HOSTILE_CONTINUATION_PAD_COEFFICIENT_COUNT,
            Self::UnusedBoundSelectorSlot => HOSTILE_BOUND_COEFFICIENT_COUNT,
            Self::AllUnusedBoundSelectorSlots => {
                HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOT_COEFFICIENT_COUNT
            }
            Self::RegisteredOpeningKernel => {
                HOSTILE_COEFFICIENT_COUNT - hostile_registered_opening_functionals().len()
            }
        }
    }
}

#[derive(Clone, Debug)]
struct IncrementalRowRank {
    column_count: usize,
    pivot_columns: Vec<usize>,
    basis_rows: Vec<Vec<u64>>,
}

impl IncrementalRowRank {
    fn new(column_count: usize) -> Self {
        Self {
            column_count,
            pivot_columns: Vec::new(),
            basis_rows: Vec::new(),
        }
    }

    fn rank(&self) -> usize {
        self.basis_rows.len()
    }

    fn add_row(&mut self, mut row: Vec<u64>) -> bool {
        assert_eq!(row.len(), self.column_count);
        for (basis_row, pivot_column) in self.basis_rows.iter().zip(&self.pivot_columns) {
            let scale = row[*pivot_column];
            if scale == 0 {
                continue;
            }
            for (value, basis_value) in row[*pivot_column..]
                .iter_mut()
                .zip(&basis_row[*pivot_column..])
            {
                *value = subtract(*value, multiply(scale, *basis_value));
            }
        }
        let Some(pivot_column) = row.iter().position(|value| *value != 0) else {
            return false;
        };
        let pivot_inverse = inverse(row[pivot_column]);
        for value in &mut row[pivot_column..] {
            *value = multiply(*value, pivot_inverse);
        }
        let insertion_index = self
            .pivot_columns
            .partition_point(|existing| *existing < pivot_column);
        self.pivot_columns.insert(insertion_index, pivot_column);
        self.basis_rows.insert(insertion_index, row);
        true
    }
}

#[derive(Clone, Debug)]
struct HostileMaskingOracle {
    additional_mask: HostileAdditionalMask,
    registered_opening_kernel: Option<RightKernelBasis>,
    mask_rank: IncrementalRowRank,
    joint_rank: IncrementalRowRank,
    mask_rows: Vec<Vec<u64>>,
    witness_rows: Vec<Vec<u64>>,
    first_deficiency: Option<HostileDeficiency>,
}

impl HostileMaskingOracle {
    fn new(additional_mask: HostileAdditionalMask) -> Self {
        let registered_opening_kernel = match additional_mask {
            HostileAdditionalMask::None
            | HostileAdditionalMask::SelectorContinuation
            | HostileAdditionalMask::UnusedBoundSelectorSlot
            | HostileAdditionalMask::AllUnusedBoundSelectorSlots => None,
            HostileAdditionalMask::RegisteredOpeningKernel => {
                // Only this variant samples from a solved kernel, so only it can
                // claim that its declared column count is the exact kernel
                // dimension. A dependent functional catalog would enlarge the
                // kernel and must fail here rather than silently widen the mask.
                let kernel = hostile_registered_opening_kernel_basis();
                assert_eq!(kernel.dimension(), additional_mask.column_count());
                Some(kernel)
            }
        };
        let mask_column_count =
            HOSTILE_PERSISTENT_MASK_COEFFICIENT_COUNT + additional_mask.column_count();
        Self {
            additional_mask,
            registered_opening_kernel,
            mask_rank: IncrementalRowRank::new(mask_column_count),
            joint_rank: IncrementalRowRank::new(
                mask_column_count + HOSTILE_WITNESS_COEFFICIENT_COUNT,
            ),
            mask_rows: Vec::new(),
            witness_rows: Vec::new(),
            first_deficiency: None,
        }
    }

    fn observe(&mut self, view: &HostileAffineView) {
        let source_functional = match &view.functional {
            HostileFunctional::Source(functional) => functional.clone(),
            HostileFunctional::Quotient(functional) => {
                quotient_functional_as_source(functional, HOSTILE_SOURCE_OPENING_POINT)
            }
        };
        let mut mask_row = (0..HOSTILE_PERSISTENT_MASK_COEFFICIENT_COUNT)
            .map(|mask_coefficient_ordinal| {
                subtract(
                    source_functional[HOSTILE_TRACE_DOMAIN_SIZE + mask_coefficient_ordinal],
                    source_functional[mask_coefficient_ordinal],
                )
            })
            .collect::<Vec<_>>();
        match (&self.additional_mask, &view.functional) {
            (HostileAdditionalMask::None, _) => {}
            (HostileAdditionalMask::SelectorContinuation, HostileFunctional::Source(_)) => {
                mask_row.extend(std::iter::repeat_n(
                    0,
                    HOSTILE_CONTINUATION_PAD_COEFFICIENT_COUNT,
                ));
            }
            (
                HostileAdditionalMask::SelectorContinuation,
                HostileFunctional::Quotient(functional),
            ) => {
                mask_row.extend_from_slice(&functional[HOSTILE_CONTINUATION_PAD_START..]);
            }
            (HostileAdditionalMask::UnusedBoundSelectorSlot, HostileFunctional::Source(_)) => {
                mask_row.extend(std::iter::repeat_n(0, HOSTILE_BOUND_COEFFICIENT_COUNT));
            }
            (
                HostileAdditionalMask::UnusedBoundSelectorSlot,
                HostileFunctional::Quotient(functional),
            ) => {
                mask_row.extend_from_slice(
                    &functional[HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START
                        ..HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_END],
                );
            }
            (HostileAdditionalMask::AllUnusedBoundSelectorSlots, HostileFunctional::Source(_)) => {
                mask_row.extend(std::iter::repeat_n(
                    0,
                    HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOT_COEFFICIENT_COUNT,
                ));
            }
            (
                HostileAdditionalMask::AllUnusedBoundSelectorSlots,
                HostileFunctional::Quotient(functional),
            ) => {
                mask_row.extend_from_slice(
                    &functional[HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOTS_START..],
                );
            }
            (HostileAdditionalMask::RegisteredOpeningKernel, HostileFunctional::Source(_)) => {
                mask_row.extend(std::iter::repeat_n(
                    0,
                    self.registered_opening_kernel
                        .as_ref()
                        .expect("registered-opening kernel exists")
                        .dimension(),
                ));
            }
            (
                HostileAdditionalMask::RegisteredOpeningKernel,
                HostileFunctional::Quotient(functional),
            ) => {
                mask_row.extend(
                    self.registered_opening_kernel
                        .as_ref()
                        .expect("registered-opening kernel exists")
                        .image_row(functional),
                );
            }
        }
        let witness_row = source_functional[..HOSTILE_WITNESS_COEFFICIENT_COUNT].to_vec();
        self.mask_rank.add_row(mask_row.clone());
        let mut joint_row = mask_row.clone();
        joint_row.extend_from_slice(&witness_row);
        self.joint_rank.add_row(joint_row);
        self.mask_rows.push(mask_row);
        self.witness_rows.push(witness_row);

        if self.first_deficiency.is_none() && self.mask_rank.rank() != self.joint_rank.rank() {
            let first_uncovered_witness_coefficient_ordinal =
                first_uncovered_witness_coefficient(&self.mask_rows, &self.witness_rows)
                    .expect("a joint-rank increase has an uncovered witness column");
            self.first_deficiency = Some(HostileDeficiency {
                identifier: view.identifier,
                observation_ordinal: self.mask_rows.len(),
                mask_rank: self.mask_rank.rank(),
                joint_rank: self.joint_rank.rank(),
                first_uncovered_witness_coefficient_ordinal,
            });
        }
    }

    fn finish(self) -> HostileOracleResult {
        HostileOracleResult {
            first_deficiency: self.first_deficiency,
            final_mask_rank: self.mask_rank.rank(),
            final_joint_rank: self.joint_rank.rank(),
        }
    }
}

fn add(left: u64, right: u64) -> u64 {
    let sum = left + right;
    if sum >= HOSTILE_FIELD_MODULUS {
        sum - HOSTILE_FIELD_MODULUS
    } else {
        sum
    }
}

fn subtract(left: u64, right: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        HOSTILE_FIELD_MODULUS - (right - left)
    }
}

fn multiply(left: u64, right: u64) -> u64 {
    (left * right) % HOSTILE_FIELD_MODULUS
}

fn power(mut base: u64, mut exponent: usize) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = multiply(result, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    result
}

fn inverse(value: u64) -> u64 {
    assert_ne!(value, 0, "only nonzero hostile-field values are inverted");
    power(value, HOSTILE_FIELD_MODULUS as usize - 2)
}

fn first_uncovered_witness_coefficient(
    mask_rows: &[Vec<u64>],
    witness_rows: &[Vec<u64>],
) -> Option<usize> {
    assert_eq!(mask_rows.len(), witness_rows.len());
    let mask_column_count = mask_rows.first().map_or(0, Vec::len);
    let mask_rank = rank_of_rows(mask_rows, mask_column_count);
    (0..HOSTILE_WITNESS_COEFFICIENT_COUNT).find(|witness_coefficient_ordinal| {
        let rows = mask_rows
            .iter()
            .zip(witness_rows)
            .map(|(mask_row, witness_row)| {
                let mut row = mask_row.clone();
                row.push(witness_row[*witness_coefficient_ordinal]);
                row
            })
            .collect::<Vec<_>>();
        rank_of_rows(&rows, mask_column_count + 1) > mask_rank
    })
}

fn rank_of_rows(rows: &[Vec<u64>], column_count: usize) -> usize {
    let mut rank = IncrementalRowRank::new(column_count);
    for row in rows {
        rank.add_row(row.clone());
    }
    rank.rank()
}

#[derive(Clone, Debug)]
struct RightKernelBasis {
    reduced_rows: Vec<Vec<u64>>,
    pivot_columns: Vec<usize>,
    free_columns: Vec<usize>,
}

impl RightKernelBasis {
    fn dimension(&self) -> usize {
        self.free_columns.len()
    }

    fn image_row(&self, functional: &[u64]) -> Vec<u64> {
        assert_eq!(
            functional.len(),
            self.reduced_rows.first().map_or(0, Vec::len)
        );
        self.free_columns
            .iter()
            .copied()
            .map(|free_column| {
                self.pivot_columns.iter().copied().enumerate().fold(
                    functional[free_column],
                    |image, (row_ordinal, pivot_column)| {
                        subtract(
                            image,
                            multiply(
                                functional[pivot_column],
                                self.reduced_rows[row_ordinal][free_column],
                            ),
                        )
                    },
                )
            })
            .collect()
    }
}

fn right_kernel_basis(rows: &[Vec<u64>], column_count: usize) -> RightKernelBasis {
    assert!(rows.iter().all(|row| row.len() == column_count));
    let mut reduced = rows.to_vec();
    let mut pivot_columns = Vec::new();
    let mut pivot_row = 0_usize;
    for column in 0..column_count {
        let Some(source_row) = (pivot_row..reduced.len()).find(|row| reduced[*row][column] != 0)
        else {
            continue;
        };
        reduced.swap(pivot_row, source_row);
        let pivot_inverse = inverse(reduced[pivot_row][column]);
        for value in &mut reduced[pivot_row][column..] {
            *value = multiply(*value, pivot_inverse);
        }
        let normalized_pivot_row = reduced[pivot_row].clone();
        for (row_ordinal, row) in reduced.iter_mut().enumerate() {
            if row_ordinal == pivot_row {
                continue;
            }
            let scale = row[column];
            if scale == 0 {
                continue;
            }
            for (value, pivot_value) in row[column..]
                .iter_mut()
                .zip(&normalized_pivot_row[column..])
            {
                *value = subtract(*value, multiply(scale, *pivot_value));
            }
        }
        pivot_columns.push(column);
        pivot_row += 1;
        if pivot_row == reduced.len() {
            break;
        }
    }
    assert_eq!(pivot_columns.len(), rows.len());

    let pivot_column_set = pivot_columns
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let free_columns = (0..column_count)
        .filter(|column| !pivot_column_set.contains(column))
        .collect();
    RightKernelBasis {
        reduced_rows: reduced,
        pivot_columns,
        free_columns,
    }
}

fn bit_at(index: usize, variable_ordinal: usize, variable_count: usize) -> usize {
    (index >> (variable_count - 1 - variable_ordinal)) & 1
}

fn equality_weight(index: usize, coordinates: &[u64]) -> u64 {
    coordinates.iter().copied().enumerate().fold(
        1_u64,
        |weight, (coordinate_ordinal, coordinate)| {
            multiply(
                weight,
                if bit_at(index, coordinate_ordinal, coordinates.len()) == 0 {
                    subtract(1, coordinate)
                } else {
                    coordinate
                },
            )
        },
    )
}

fn multilinear_evaluation_functional(coordinates: &[u64]) -> Vec<u64> {
    (0..1_usize << coordinates.len())
        .map(|index| equality_weight(index, coordinates))
        .collect()
}

fn expand_from_univariate(mut point: u64, variable_count: usize) -> Vec<u64> {
    let mut coordinates = vec![0_u64; variable_count];
    for coordinate in coordinates.iter_mut().rev() {
        *coordinate = point;
        point = multiply(point, point);
    }
    coordinates
}

fn polynomial_opening_point(mut point: u64, variable_count: usize) -> Vec<u64> {
    let mut coordinates = Vec::with_capacity(variable_count);
    for _ in 0..variable_count {
        let denominator = add(1, point);
        assert_ne!(
            denominator, 0,
            "hostile opening point avoids reduction poles"
        );
        coordinates.push(multiply(point, inverse(denominator)));
        point = multiply(point, point);
    }
    coordinates.reverse();
    coordinates
}

fn source_evaluation_functional(point: u64) -> Vec<u64> {
    (0..HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE)
        .map(|coefficient_ordinal| power(point, coefficient_ordinal))
        .collect()
}

fn quotient_functional_as_source(functional: &[u64], opening_point: u64) -> Vec<u64> {
    assert_eq!(functional.len(), HOSTILE_COEFFICIENT_COUNT);
    let mut source_functional = vec![0_u64; HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE];
    for (source_coefficient_ordinal, source_weight) in
        source_functional.iter_mut().enumerate().skip(1)
    {
        let mut opening_power = 1_u64;
        for quotient_coefficient_ordinal in (0..source_coefficient_ordinal).rev() {
            if quotient_coefficient_ordinal < HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE {
                *source_weight = add(
                    *source_weight,
                    multiply(functional[quotient_coefficient_ordinal], opening_power),
                );
            }
            opening_power = multiply(opening_power, opening_point);
        }
    }
    source_functional
}

fn lift_current_functional(
    current_functional: &[u64],
    folded_prefix_challenges: &[u64],
) -> Vec<u64> {
    assert_eq!(
        current_functional.len(),
        1_usize << (HOSTILE_VARIABLE_COUNT - folded_prefix_challenges.len())
    );
    let mut functional = vec![0_u64; HOSTILE_COEFFICIENT_COUNT];
    for prefix_index in 0..1_usize << folded_prefix_challenges.len() {
        let prefix_weight = equality_weight(prefix_index, folded_prefix_challenges);
        let destination_start = prefix_index * current_functional.len();
        for (destination, current) in functional
            [destination_start..destination_start + current_functional.len()]
            .iter_mut()
            .zip(current_functional)
        {
            *destination = multiply(prefix_weight, *current);
        }
    }
    functional
}

fn fold_dense(values: &[u64], challenge: u64) -> Vec<u64> {
    assert!(values.len().is_power_of_two() && values.len() >= 2);
    let half = values.len() / 2;
    (0..half)
        .map(|index| {
            add(
                values[index],
                multiply(challenge, subtract(values[half + index], values[index])),
            )
        })
        .collect()
}

fn prefix_dft_functional(
    folded_prefix_challenges: &[u64],
    source_column_ordinal: usize,
    query_index: usize,
    inverse_rate: usize,
) -> Vec<u64> {
    let remaining_variable_count = HOSTILE_VARIABLE_COUNT - folded_prefix_challenges.len();
    assert!(remaining_variable_count >= HOSTILE_INITIAL_FOLDING_FACTOR);
    let source_width = 1_usize << HOSTILE_INITIAL_FOLDING_FACTOR;
    assert!(source_column_ordinal < source_width);
    let source_height = 1_usize << (remaining_variable_count - HOSTILE_INITIAL_FOLDING_FACTOR);
    let encoded_height = source_height * inverse_rate;
    assert!(encoded_height.is_power_of_two());
    let encoded_generator = power(
        HOSTILE_FIELD_GENERATOR,
        (HOSTILE_FIELD_MODULUS as usize - 1) / encoded_height,
    );
    let evaluation_point = power(encoded_generator, query_index % encoded_height);
    let mut current_functional = vec![0_u64; 1 << remaining_variable_count];
    let source_start = source_column_ordinal * source_height;
    for source_coefficient_ordinal in 0..source_height {
        current_functional[source_start + source_coefficient_ordinal] =
            power(evaluation_point, source_coefficient_ordinal);
    }
    lift_current_functional(&current_functional, folded_prefix_challenges)
}

fn sumcheck_functionals(weights: &[u64], folded_prefix_challenges: &[u64]) -> (Vec<u64>, Vec<u64>) {
    assert_eq!(
        weights.len(),
        1_usize << (HOSTILE_VARIABLE_COUNT - folded_prefix_challenges.len())
    );
    let half = weights.len() / 2;
    let mut constant = vec![0_u64; weights.len()];
    let mut quadratic = vec![0_u64; weights.len()];
    for index in 0..half {
        constant[index] = weights[index];
        quadratic[index] = subtract(weights[index], weights[half + index]);
        quadratic[half + index] = subtract(weights[half + index], weights[index]);
    }
    (
        lift_current_functional(&constant, folded_prefix_challenges),
        lift_current_functional(&quadratic, folded_prefix_challenges),
    )
}

fn combine_constraint_weights(
    carried_weights: &[u64],
    select_points: &[u64],
    combination_challenge: u64,
) -> Vec<u64> {
    let carried_multiplier = power(combination_challenge, select_points.len());
    let mut combined = carried_weights
        .iter()
        .map(|weight| multiply(carried_multiplier, *weight))
        .collect::<Vec<_>>();
    for (constraint_ordinal, point) in select_points.iter().copied().enumerate() {
        let constraint_multiplier = power(combination_challenge, constraint_ordinal);
        for (index, weight) in combined.iter_mut().enumerate() {
            *weight = add(
                *weight,
                multiply(constraint_multiplier, power(point, index)),
            );
        }
    }
    combined
}

fn append_source_view(views: &mut Vec<HostileAffineView>, identifier: HostileView, point: u64) {
    views.push(HostileAffineView {
        identifier,
        functional: HostileFunctional::Source(source_evaluation_functional(point)),
    });
}

fn append_quotient_view(
    views: &mut Vec<HostileAffineView>,
    identifier: HostileView,
    functional: Vec<u64>,
) {
    views.push(HostileAffineView {
        identifier,
        functional: HostileFunctional::Quotient(functional),
    });
}

fn hostile_bound_evaluation_points() -> Vec<u64> {
    let coset_offset = power(HOSTILE_FIELD_GENERATOR, 1 << 18);
    let domain_size = HOSTILE_BOUND_LEAF_COUNT * 2;
    let domain_generator = power(
        HOSTILE_FIELD_GENERATOR,
        (HOSTILE_FIELD_MODULUS as usize - 1) / domain_size,
    );
    HOSTILE_BOUND_QUERY_LEAF_INDICES
        .into_iter()
        .flat_map(|leaf_index| [leaf_index, leaf_index + HOSTILE_BOUND_LEAF_COUNT])
        .map(|position| multiply(coset_offset, power(domain_generator, position)))
        .collect()
}

fn hostile_registered_points(bound_evaluation_points: &[u64]) -> Vec<Vec<u64>> {
    let mut points = bound_evaluation_points
        .iter()
        .copied()
        .map(|point| {
            let mut coordinates = vec![0_u64; 4];
            coordinates.extend(polynomial_opening_point(
                point,
                HOSTILE_BOUND_VARIABLE_COUNT,
            ));
            coordinates
        })
        .collect::<Vec<_>>();
    let mut boundary = vec![0_u64; 4];
    boundary.extend((0..HOSTILE_BOUND_VARIABLE_COUNT).map(|variable_ordinal| {
        bit_at(
            HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE,
            variable_ordinal,
            HOSTILE_BOUND_VARIABLE_COUNT,
        ) as u64
    }));
    points.push(boundary);
    let mut later_coefficient_subcube = vec![0_u64; 4];
    later_coefficient_subcube.extend([1, 1]);
    later_coefficient_subcube.extend(expand_from_univariate(
        127,
        HOSTILE_BOUND_VARIABLE_COUNT - 2,
    ));
    points.push(later_coefficient_subcube);
    assert!(
        points
            .iter()
            .all(|point| point.len() == HOSTILE_VARIABLE_COUNT && point[0] == 0)
    );
    points
}

fn hostile_registered_opening_functionals() -> Vec<Vec<u64>> {
    hostile_registered_points(&hostile_bound_evaluation_points())
        .iter()
        .map(|point| multilinear_evaluation_functional(point))
        .collect()
}

fn hostile_registered_points_for_both_used_bound_slots() -> Vec<Vec<u64>> {
    hostile_registered_points(&hostile_bound_evaluation_points())
        .into_iter()
        .flat_map(|input_point| {
            let mut output_point = input_point.clone();
            output_point[3] = 1;
            [input_point, output_point]
        })
        .collect()
}

fn hostile_registered_opening_kernel_basis() -> RightKernelBasis {
    let opening_functionals = hostile_registered_opening_functionals();
    let basis = right_kernel_basis(&opening_functionals, HOSTILE_COEFFICIENT_COUNT);
    assert_eq!(
        basis.dimension(),
        HOSTILE_COEFFICIENT_COUNT - opening_functionals.len()
    );
    assert!(opening_functionals.iter().all(|functional| {
        basis
            .image_row(functional)
            .iter()
            .all(|coordinate| *coordinate == 0)
    }));
    basis
}

fn hostile_complete_view_catalog() -> Vec<HostileAffineView> {
    let mut views = Vec::new();
    append_source_view(
        &mut views,
        HostileView::SourceOpening,
        HOSTILE_SOURCE_OPENING_POINT,
    );
    let bound_evaluation_points = hostile_bound_evaluation_points();
    for (evaluation_ordinal, point) in bound_evaluation_points.iter().copied().enumerate() {
        append_source_view(
            &mut views,
            HostileView::BoundLeafValue {
                query_ordinal: evaluation_ordinal / 2,
                opposite: evaluation_ordinal & 1 == 1,
            },
            point,
        );
    }

    let registered_points = hostile_registered_points(&bound_evaluation_points);
    let opening_batch_challenge = 73;
    let mut weights = vec![0_u64; HOSTILE_COEFFICIENT_COUNT];
    for (claim_ordinal, point) in registered_points.iter().enumerate() {
        let claim_multiplier = power(opening_batch_challenge, claim_ordinal);
        for (weight, claim_weight) in weights
            .iter_mut()
            .zip(multilinear_evaluation_functional(point))
        {
            *weight = add(*weight, multiply(claim_multiplier, claim_weight));
        }
    }
    let mut folded_prefix_challenges = Vec::new();
    for (round_ordinal, challenge) in HOSTILE_INITIAL_FOLD_CHALLENGES.iter().copied().enumerate() {
        let (constant, quadratic) = sumcheck_functionals(&weights, &folded_prefix_challenges);
        append_quotient_view(
            &mut views,
            HostileView::InitialSumcheck {
                round_ordinal,
                coefficient: HostileSumcheckCoefficient::Constant,
            },
            constant,
        );
        append_quotient_view(
            &mut views,
            HostileView::InitialSumcheck {
                round_ordinal,
                coefficient: HostileSumcheckCoefficient::Quadratic,
            },
            quadratic,
        );
        weights = fold_dense(&weights, challenge);
        folded_prefix_challenges.push(challenge);
    }

    for round_ordinal in 0..HOSTILE_ROUND_COUNT {
        let inverse_rate = 4_usize << (2 * round_ordinal);
        let previous_commitment_prefix_count = round_ordinal * HOSTILE_INITIAL_FOLDING_FACTOR;
        let previous_commitment_prefix =
            &folded_prefix_challenges[..previous_commitment_prefix_count];
        let remaining_variable_count = HOSTILE_VARIABLE_COUNT - folded_prefix_challenges.len();
        let query_domain_size = (1_usize << remaining_variable_count) * inverse_rate;
        let query_domain_generator = power(
            HOSTILE_FIELD_GENERATOR,
            (HOSTILE_FIELD_MODULUS as usize - 1) / query_domain_size,
        );
        let mut select_points = Vec::with_capacity(HOSTILE_WHIR_QUERY_COUNT);
        for (query_ordinal, query_index) in HOSTILE_QUERY_INDICES[round_ordinal]
            .iter()
            .copied()
            .enumerate()
        {
            for leaf_value_ordinal in 0..1 << HOSTILE_INITIAL_FOLDING_FACTOR {
                append_quotient_view(
                    &mut views,
                    HostileView::WhirQuery {
                        epoch_ordinal: round_ordinal,
                        query_ordinal,
                        leaf_value_ordinal,
                    },
                    prefix_dft_functional(
                        previous_commitment_prefix,
                        leaf_value_ordinal,
                        query_index,
                        inverse_rate,
                    ),
                );
            }
            select_points.push(power(query_domain_generator, query_index));
        }
        weights = combine_constraint_weights(
            &weights,
            &select_points,
            HOSTILE_ROUND_COMBINATION_CHALLENGES[round_ordinal],
        );
        for (sumcheck_round_ordinal, challenge) in HOSTILE_ROUND_FOLD_CHALLENGES[round_ordinal]
            .iter()
            .copied()
            .enumerate()
        {
            let (constant, quadratic) = sumcheck_functionals(&weights, &folded_prefix_challenges);
            append_quotient_view(
                &mut views,
                HostileView::RoundSumcheck {
                    round_ordinal,
                    sumcheck_round_ordinal,
                    coefficient: HostileSumcheckCoefficient::Constant,
                },
                constant,
            );
            append_quotient_view(
                &mut views,
                HostileView::RoundSumcheck {
                    round_ordinal,
                    sumcheck_round_ordinal,
                    coefficient: HostileSumcheckCoefficient::Quadratic,
                },
                quadratic,
            );
            weights = fold_dense(&weights, challenge);
            folded_prefix_challenges.push(challenge);
        }
    }

    let final_coefficient_count =
        1_usize << (HOSTILE_VARIABLE_COUNT - folded_prefix_challenges.len());
    for coefficient_ordinal in 0..final_coefficient_count {
        let mut current_functional = vec![0_u64; final_coefficient_count];
        current_functional[coefficient_ordinal] = 1;
        append_quotient_view(
            &mut views,
            HostileView::FinalCoefficient {
                coefficient_ordinal,
            },
            lift_current_functional(&current_functional, &folded_prefix_challenges),
        );
    }
    let final_previous_prefix_count = HOSTILE_ROUND_COUNT * HOSTILE_INITIAL_FOLDING_FACTOR;
    let final_previous_prefix = &folded_prefix_challenges[..final_previous_prefix_count];
    let final_inverse_rate = 4_usize << (2 * HOSTILE_ROUND_COUNT);
    for (query_ordinal, query_index) in HOSTILE_QUERY_INDICES[HOSTILE_ROUND_COUNT]
        .iter()
        .copied()
        .enumerate()
    {
        for leaf_value_ordinal in 0..1 << HOSTILE_INITIAL_FOLDING_FACTOR {
            append_quotient_view(
                &mut views,
                HostileView::FinalQuery {
                    query_ordinal,
                    leaf_value_ordinal,
                },
                prefix_dft_functional(
                    final_previous_prefix,
                    leaf_value_ordinal,
                    query_index,
                    final_inverse_rate,
                ),
            );
        }
    }
    for (round_ordinal, challenge) in HOSTILE_FINAL_FOLD_CHALLENGES.iter().copied().enumerate() {
        let (constant, quadratic) = sumcheck_functionals(&weights, &folded_prefix_challenges);
        append_quotient_view(
            &mut views,
            HostileView::FinalSumcheck {
                round_ordinal,
                coefficient: HostileSumcheckCoefficient::Constant,
            },
            constant,
        );
        append_quotient_view(
            &mut views,
            HostileView::FinalSumcheck {
                round_ordinal,
                coefficient: HostileSumcheckCoefficient::Quadratic,
            },
            quadratic,
        );
        weights = fold_dense(&weights, challenge);
        folded_prefix_challenges.push(challenge);
    }
    assert_eq!(folded_prefix_challenges.len(), HOSTILE_VARIABLE_COUNT);
    assert_eq!(weights.len(), 1);
    views
}

fn analyze_hostile_catalog(
    views: &[HostileAffineView],
    additional_mask: HostileAdditionalMask,
) -> HostileOracleResult {
    let mut oracle = HostileMaskingOracle::new(additional_mask);
    for view in views {
        oracle.observe(view);
    }
    oracle.finish()
}

fn selected_same_secret_construction_plan() -> RowCodeWhirConstructionPlan {
    let context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("selected same-secret relation context");
    let relation_plan = compile_same_secret_relation_plan(
        &selected_same_secret_relation_plan_input().expect("selected same-secret relation input"),
        &context,
    )
    .expect("compile selected same-secret relation");
    let artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(relation_plan, &context)
        .expect("validate selected same-secret relation");
    let variant = artifact
        .compiled_plan()
        .select_variant(None, None)
        .expect("select same-secret relation variant");
    RowCodeWhirConstructionPlan::for_selected_variant(
        &artifact,
        variant.schedule_position(),
        variant.top_count(),
    )
    .expect("derive selected same-secret construction plan")
}

fn assert_hostile_model_scales_selected_geometry(plan: &RowCodeWhirConstructionPlan) {
    let persistent_mask_coefficient_count = usize::try_from(
        selected_committed_material_relation_plan_input()
            .expect("selected committed-material relation input")
            .trace_mask_degree_bound_exclusive,
    )
    .expect("selected persistent mask count fits usize");
    assert_eq!(persistent_mask_coefficient_count, 2_048);
    assert_eq!(plan.bound_reduction_blocks.len(), 2);
    assert_eq!(plan.bound_reduction_blocks[0].selector_prefix, [0, 0, 0, 0]);
    assert_eq!(plan.bound_reduction_blocks[0].query_count, 40);
    assert_eq!(
        plan.bound_reduction_blocks[0].maximum_source_degree_bound_exclusive,
        18_432
    );
    assert_eq!(
        plan.bound_reduction_blocks[0].quotient_degree_bound_exclusive,
        18_431
    );
    assert_eq!(plan.bound_trees[0].source_trace_domain_size, 16_384);
    assert_eq!(plan.parameters.table_variable_count, 19);
    assert_eq!(plan.parameters.polynomial_commitment_variable_count, 21);
    assert_eq!(plan.parameters.folding_factor, 3);
    assert_eq!(plan.parameters.outer_query_count, 387);
    assert_eq!(plan.whir.initial_out_of_domain_sample_count, 0);
    assert_eq!(plan.whir.initial_sumcheck_round_count, 3);
    assert_eq!(plan.whir.rounds.len(), 4);
    assert!(
        plan.whir
            .rounds
            .iter()
            .all(|round| round.out_of_domain_sample_count == 0
                && round.following_sumcheck_round_count == 3)
    );
    assert_eq!(plan.whir.rounds[0].query_epoch.query_count, 387);
    assert_eq!(plan.whir.rounds[0].encoded_oracle.leaf_width, 8);
    assert_eq!(plan.whir.final_round.encoded_oracle.leaf_width, 8);
    assert_eq!(plan.whir.final_round.revealed_coefficient_count, 64);
    assert_eq!(plan.whir.final_round.sumcheck_round_count, 6);

    assert_eq!(
        HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE - HOSTILE_TRACE_DOMAIN_SIZE,
        HOSTILE_PERSISTENT_MASK_COEFFICIENT_COUNT
    );
    assert_eq!(
        HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE,
        HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE - 1
    );
    assert_eq!(
        HOSTILE_INITIAL_FOLDING_FACTOR,
        plan.parameters.folding_factor
    );
}

fn direct_divide_source_at_opening(source: &[u64], opening_point: u64) -> Vec<u64> {
    assert_eq!(source.len(), HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE);
    let mut quotient = vec![0_u64; HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE];
    quotient[HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE - 1] =
        source[HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE - 1];
    for coefficient_ordinal in (1..HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE).rev() {
        quotient[coefficient_ordinal - 1] = add(
            source[coefficient_ordinal],
            multiply(opening_point, quotient[coefficient_ordinal]),
        );
    }
    quotient
}

fn dot_product(left: &[u64], right: &[u64]) -> u64 {
    assert_eq!(left.len(), right.len());
    left.iter().zip(right).fold(0_u64, |sum, (left, right)| {
        add(sum, multiply(*left, *right))
    })
}

#[test]
fn hostile_quotient_functional_matches_independent_synthetic_division() {
    let source = (0..HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE)
        .map(|coefficient_ordinal| {
            ((coefficient_ordinal as u64 + 3) * (coefficient_ordinal as u64 + 11))
                % HOSTILE_FIELD_MODULUS
        })
        .collect::<Vec<_>>();
    let quotient = direct_divide_source_at_opening(&source, HOSTILE_SOURCE_OPENING_POINT);
    let mut quotient_functional = vec![0_u64; HOSTILE_COEFFICIENT_COUNT];
    for (coefficient_ordinal, coefficient) in quotient_functional
        [..HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE]
        .iter_mut()
        .enumerate()
    {
        *coefficient = ((coefficient_ordinal as u64 + 5) * (2 * coefficient_ordinal as u64 + 17))
            % HOSTILE_FIELD_MODULUS;
    }
    let source_functional =
        quotient_functional_as_source(&quotient_functional, HOSTILE_SOURCE_OPENING_POINT);
    assert_eq!(
        dot_product(
            &quotient_functional[..HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE],
            &quotient,
        ),
        dot_product(&source_functional, &source),
    );

    for mask_coefficient_ordinal in [0, 1, 17, 63] {
        let mut masked_source = vec![0_u64; HOSTILE_SOURCE_DEGREE_BOUND_EXCLUSIVE];
        masked_source[mask_coefficient_ordinal] = subtract(0, 1);
        masked_source[HOSTILE_TRACE_DOMAIN_SIZE + mask_coefficient_ordinal] = 1;
        let masked_quotient =
            direct_divide_source_at_opening(&masked_source, HOSTILE_SOURCE_OPENING_POINT);
        assert_eq!(
            dot_product(
                &quotient_functional[..HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE],
                &masked_quotient,
            ),
            subtract(
                source_functional[HOSTILE_TRACE_DOMAIN_SIZE + mask_coefficient_ordinal],
                source_functional[mask_coefficient_ordinal],
            ),
        );
    }
}

#[test]
fn selected_same_secret_continuation_pad_has_an_initial_epoch_counterexample() {
    let views = hostile_complete_view_catalog();
    let incumbent = analyze_hostile_catalog(&views, HostileAdditionalMask::None);
    let continuation_candidate =
        analyze_hostile_catalog(&views, HostileAdditionalMask::SelectorContinuation);
    let incumbent_deficiency = incumbent
        .first_deficiency
        .expect("the incumbent mask image is deficient");
    let candidate_deficiency = continuation_candidate
        .first_deficiency
        .expect("the proposed continuation pad remains deficient");
    assert_eq!(
        incumbent_deficiency.identifier,
        candidate_deficiency.identifier
    );
    assert_eq!(
        candidate_deficiency,
        HostileDeficiency {
            identifier: HostileView::WhirQuery {
                epoch_ordinal: 0,
                query_ordinal: 3,
                leaf_value_ordinal: 0,
            },
            observation_ordinal: 36,
            mask_rank: 23,
            joint_rank: 24,
            first_uncovered_witness_coefficient_ordinal: 0,
        }
    );
    assert!(matches!(
        candidate_deficiency.identifier,
        HostileView::WhirQuery {
            epoch_ordinal: 0,
            leaf_value_ordinal: 0,
            ..
        }
    ));
    assert_eq!(
        candidate_deficiency.joint_rank,
        candidate_deficiency.mask_rank + 1
    );
    assert_eq!(
        (
            continuation_candidate.final_mask_rank,
            continuation_candidate.final_joint_rank,
        ),
        (106, 107),
        "a later mask row must not erase the first affine-image failure"
    );

    let deficient_view = &views[candidate_deficiency.observation_ordinal - 1];
    let HostileFunctional::Quotient(functional) = &deficient_view.functional else {
        panic!("the first deficiency must be a quotient-column WHIR view");
    };
    assert!(
        functional[HOSTILE_CONTINUATION_PAD_START..]
            .iter()
            .all(|coefficient| *coefficient == 0),
        "the x0 continuation has zero image on the deficient low-prefix opening"
    );

    let selected_plan = selected_same_secret_construction_plan();
    assert_hostile_model_scales_selected_geometry(&selected_plan);
}

#[test]
fn unused_bound_selector_slot_is_a_registered_claim_kernel_but_not_a_masking_repair() {
    let selected_plan = selected_same_secret_construction_plan();
    assert_hostile_model_scales_selected_geometry(&selected_plan);
    assert_eq!(
        selected_plan.bound_reduction_blocks[0].selector_prefix,
        [0, 0, 0, 0]
    );
    assert_eq!(
        selected_plan.bound_reduction_blocks[1].selector_prefix,
        [0, 0, 0, 1]
    );

    for point in hostile_registered_points_for_both_used_bound_slots() {
        let functional = multilinear_evaluation_functional(&point);
        assert!(
            functional
                [HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START..HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_END]
                .iter()
                .all(|coefficient| *coefficient == 0),
            "the unused 0010 selector slot must vanish at every registered 0000/0001 point",
        );
    }

    let views = hostile_complete_view_catalog();
    let result = analyze_hostile_catalog(&views, HostileAdditionalMask::UnusedBoundSelectorSlot);
    let deficiency = result
        .first_deficiency
        .expect("the unused 0010 selector slot remains deficient");
    assert_eq!(
        deficiency,
        HostileDeficiency {
            identifier: HostileView::WhirQuery {
                epoch_ordinal: 0,
                query_ordinal: 3,
                leaf_value_ordinal: 0,
            },
            observation_ordinal: 36,
            mask_rank: 12,
            joint_rank: 13,
            first_uncovered_witness_coefficient_ordinal: 0,
        }
    );
    assert_eq!((result.final_mask_rank, result.final_joint_rank), (74, 75));

    let HostileFunctional::Quotient(deficient_functional) =
        &views[deficiency.observation_ordinal - 1].functional
    else {
        panic!("the first selector-slot deficiency must be a quotient-column WHIR view");
    };
    assert!(
        deficient_functional
            [HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_START..HOSTILE_UNUSED_BOUND_SELECTOR_SLOT_END]
            .iter()
            .all(|coefficient| *coefficient == 0),
        "epoch-zero leaf zero has identically zero image on the unused 0010 selector slot",
    );
}

#[test]
fn all_unused_bound_selector_slots_leave_the_same_epoch_zero_deficiency() {
    for point in hostile_registered_points_for_both_used_bound_slots() {
        let functional = multilinear_evaluation_functional(&point);
        assert!(
            functional[HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOTS_START..]
                .iter()
                .all(|coefficient| *coefficient == 0),
            "every currently unused selector slot must vanish at registered 0000/0001 points",
        );
    }

    let views = hostile_complete_view_catalog();
    let result =
        analyze_hostile_catalog(&views, HostileAdditionalMask::AllUnusedBoundSelectorSlots);
    let deficiency = result
        .first_deficiency
        .expect("the direct sum of all unused selector slots remains deficient");
    assert_eq!(
        deficiency,
        HostileDeficiency {
            identifier: HostileView::WhirQuery {
                epoch_ordinal: 0,
                query_ordinal: 3,
                leaf_value_ordinal: 0,
            },
            observation_ordinal: 36,
            mask_rank: 32,
            joint_rank: 33,
            first_uncovered_witness_coefficient_ordinal: 0,
        }
    );
    assert_eq!(
        (result.final_mask_rank, result.final_joint_rank),
        (118, 119)
    );

    let HostileFunctional::Quotient(deficient_functional) =
        &views[deficiency.observation_ordinal - 1].functional
    else {
        panic!("the first all-unused-slot deficiency must be a quotient-column WHIR view");
    };
    assert!(
        deficient_functional[HOSTILE_ALL_UNUSED_BOUND_SELECTOR_SLOTS_START..]
            .iter()
            .all(|coefficient| *coefficient == 0),
        "epoch-zero leaf zero has identically zero image on every currently unused selector slot",
    );
}

#[test]
fn registered_opening_kernel_masks_the_complete_hostile_whir_view() {
    let opening_functionals = hostile_registered_opening_functionals();
    let kernel_basis = hostile_registered_opening_kernel_basis();
    assert_eq!(
        rank_of_rows(&opening_functionals, HOSTILE_COEFFICIENT_COUNT),
        opening_functionals.len(),
        "the hostile opening constraints must be independent",
    );
    assert_eq!(
        kernel_basis.dimension(),
        HOSTILE_COEFFICIENT_COUNT - opening_functionals.len(),
    );
    for (opening_ordinal, functional) in opening_functionals.iter().enumerate() {
        assert!(
            kernel_basis
                .image_row(functional)
                .iter()
                .all(|coefficient| *coefficient == 0),
            "registered opening {opening_ordinal} has a nonzero kernel image",
        );
    }

    let result = analyze_hostile_catalog(
        &hostile_complete_view_catalog(),
        HostileAdditionalMask::RegisteredOpeningKernel,
    );
    assert_eq!(result.first_deficiency, None);
    assert_eq!(result.final_mask_rank, result.final_joint_rank);
    assert!(result.final_mask_rank > 0);
}

/// Establishes why no row pad can repair the first-epoch deficiency.
///
/// The deficient view is a WHIR query answer. Every query vector is drawn from
/// the transcript only after the aggregate commitment has been observed, and the
/// aggregate is committed only after all three phase roots, which the relation
/// prefix schedule owns and which therefore precede every row-code WHIR
/// operation in the catalog. A row pad is fixed inside the phase rows it masks,
/// so it is committed strictly before the functional it would have to cancel
/// even exists. A registered-opening kernel cannot be sampled for these views at
/// any point in the production chronology, whatever its rank properties are in
/// the reduced hostile model. The repair belongs to the mask groups that are
/// committed with the aggregate, which is where the construction already
/// reserves a hiding-WHIR soundness component.
#[test]
fn every_query_functional_becomes_known_only_after_the_aggregate_commitment() {
    let plan = selected_same_secret_construction_plan();
    let operations = plan.transcript_operations();
    let aggregate_commitment_ordinal = operations
        .iter()
        .position(|operation| {
            matches!(
                operation,
                super::construction_plan::RowCodeWhirTranscriptOperation::ObserveCommitment {
                    role: super::construction_plan::RowCodeWhirCommitmentRole::Aggregate,
                }
            )
        })
        .expect("the plan observes the aggregate commitment");
    let query_draw_ordinals = operations
        .iter()
        .enumerate()
        .filter(|(_, operation)| {
            matches!(
                operation,
                super::construction_plan::RowCodeWhirTranscriptOperation::SampleDistinctIndices {
                    ..
                }
            )
        })
        .map(|(ordinal, _)| ordinal)
        .collect::<Vec<_>>();
    assert!(
        !query_draw_ordinals.is_empty(),
        "the plan draws at least one query vector"
    );
    assert!(
        query_draw_ordinals
            .iter()
            .all(|ordinal| *ordinal > aggregate_commitment_ordinal),
        "the aggregate commitment is observed at operation {aggregate_commitment_ordinal},          but query vectors are drawn at {query_draw_ordinals:?}",
    );
    // The three phase roots belong to the relation prefix schedule, so they are
    // absorbed before any row-code WHIR operation exists.
    assert_eq!(plan.phase_order.len(), 3);
}

#[test]
fn continuation_pad_is_in_every_registered_selector_three_point_kernel() {
    let bound_evaluation_points = hostile_bound_evaluation_points();
    for point in hostile_registered_points(&bound_evaluation_points) {
        let functional = multilinear_evaluation_functional(&point);
        assert!(
            functional[HOSTILE_CONTINUATION_PAD_START..]
                .iter()
                .all(|coefficient| *coefficient == 0)
        );
    }
    let low_prefix_query = prefix_dft_functional(&[], 0, HOSTILE_QUERY_INDICES[0][0], 4);
    assert!(
        low_prefix_query[HOSTILE_CONTINUATION_PAD_START..]
            .iter()
            .all(|coefficient| *coefficient == 0)
    );
    assert!(
        low_prefix_query[..HOSTILE_QUOTIENT_DEGREE_BOUND_EXCLUSIVE]
            .iter()
            .any(|coefficient| *coefficient != 0)
    );
}
