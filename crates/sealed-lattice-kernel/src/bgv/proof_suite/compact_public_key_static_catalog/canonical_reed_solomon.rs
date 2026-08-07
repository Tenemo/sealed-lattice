//! Deterministic Reed-Solomon correction used by the compact extractor.
//!
//! The compact CFW and hiding-WHIR theorem uses the complete
//! `message || hiding randomness` coefficient dimension. This owner evaluates
//! that exact code on the canonical two-adic Goldilocks domain and executes a
//! fixed Berlekamp-Welch decoder. It is deliberately independent of the prover
//! commitment implementation: the extractor consumes field-valued oracle
//! rows, reconstructs every interleaved coefficient column, re-encodes it, and
//! checks the shared row-error radius before returning a witness.

use crate::bgv::proof_suite::field::{
    PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR, ProofBaseFieldElement,
    ProofChallengeExtensionElement,
};

const GOLDILOCKS_TWO_ADICITY: u32 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CanonicalReedSolomonError {
    ArithmeticOverflow,
    InconsistentLinearSystem,
    InvalidGeometry,
    MalformedOracle,
    NonCodewordQuotient,
    OutsideDecodingRadius,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CanonicalReedSolomonGeometry {
    message_length: usize,
    hiding_randomness_length: usize,
    block_length: usize,
    interleaving_width: usize,
}

impl CanonicalReedSolomonGeometry {
    pub(super) fn new(
        message_length: usize,
        hiding_randomness_length: usize,
        block_length: usize,
        interleaving_width: usize,
    ) -> Result<Self, CanonicalReedSolomonError> {
        let dimension = message_length
            .checked_add(hiding_randomness_length)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let block_length_exceeds_field_two_adicity = u64::try_from(block_length)
            .map(|length| length > (1_u64 << GOLDILOCKS_TWO_ADICITY))
            .unwrap_or(true);
        if message_length == 0
            || hiding_randomness_length == 0
            || interleaving_width == 0
            || !block_length.is_power_of_two()
            || block_length_exceeds_field_two_adicity
            || dimension >= block_length
        {
            return Err(CanonicalReedSolomonError::InvalidGeometry);
        }
        Ok(Self {
            message_length,
            hiding_randomness_length,
            block_length,
            interleaving_width,
        })
    }

    pub(super) const fn message_length(self) -> usize {
        self.message_length
    }

    pub(super) const fn hiding_randomness_length(self) -> usize {
        self.hiding_randomness_length
    }

    pub(super) const fn block_length(self) -> usize {
        self.block_length
    }

    pub(super) const fn interleaving_width(self) -> usize {
        self.interleaving_width
    }

    pub(super) fn dimension(self) -> usize {
        self.message_length + self.hiding_randomness_length
    }

    pub(super) fn selected_decoding_error_count(self) -> usize {
        (self.block_length - self.dimension() - 1) / 2
    }

    /// Exact field-operation count of the canonical encoder for this geometry.
    pub(super) fn encoding_field_operation_count(self) -> Result<u128, CanonicalReedSolomonError> {
        let evaluation_point_operation_count =
            canonical_evaluation_point_field_operation_count(self)?;
        evaluation_point_operation_count
            .checked_add(canonical_horner_field_operation_count(
                self.block_length,
                self.interleaving_width,
                self.dimension(),
            )?)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
    }

    /// Worst-case field-operation count of the canonical Berlekamp-Welch
    /// decoder, including both re-encodings performed by the executable
    /// implementation.
    pub(super) fn decoding_field_operation_bound(self) -> Result<u128, CanonicalReedSolomonError> {
        let block_length = u128::try_from(self.block_length)
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let interleaving_width = u128::try_from(self.interleaving_width)
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let dimension = u128::try_from(self.dimension())
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let maximum_error_count = u128::try_from(self.selected_decoding_error_count())
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let unknown_count = dimension
            .checked_add(
                maximum_error_count
                    .checked_mul(2)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
            )
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;

        let per_row_system_construction = dimension
            .checked_add(
                maximum_error_count
                    .checked_mul(3)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_add(1))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let system_construction_bound = block_length
            .checked_mul(per_row_system_construction)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let elimination_bound =
            canonical_linear_system_field_operation_bound(block_length, unknown_count)?;
        let division_bound = dimension
            .checked_mul(
                maximum_error_count
                    .checked_add(1)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_mul(2))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let per_component_reencoding_bound = block_length
            .checked_mul(dimension)
            .and_then(|count| count.checked_mul(2))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let per_component_bound = system_construction_bound
            .checked_add(elimination_bound)
            .and_then(|count| count.checked_add(division_bound))
            .and_then(|count| count.checked_add(per_component_reencoding_bound))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let final_interleaved_reencoding_bound = per_component_reencoding_bound
            .checked_mul(interleaving_width)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;

        canonical_evaluation_point_field_operation_count(self)?
            .checked_add(
                per_component_bound
                    .checked_mul(interleaving_width)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_add(final_interleaved_reencoding_bound))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
    }

    /// Worst-case field-operation count of the canonical erasure corrector for
    /// an exact retained-position count.
    pub(super) fn erasure_correction_field_operation_bound(
        self,
        retained_position_count: usize,
    ) -> Result<u128, CanonicalReedSolomonError> {
        if retained_position_count < self.dimension() || retained_position_count > self.block_length
        {
            return Err(CanonicalReedSolomonError::InvalidGeometry);
        }
        let retained_position_count = u128::try_from(retained_position_count)
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let interleaving_width = u128::try_from(self.interleaving_width)
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let dimension = u128::try_from(self.dimension())
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        let system_construction_bound = retained_position_count
            .checked_mul(dimension)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let elimination_bound =
            canonical_linear_system_field_operation_bound(retained_position_count, dimension)?;
        let per_component_bound = system_construction_bound
            .checked_add(elimination_bound)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let final_interleaved_reencoding_bound = canonical_horner_field_operation_count(
            self.block_length,
            self.interleaving_width,
            self.dimension(),
        )?;

        canonical_evaluation_point_field_operation_count(self)?
            .checked_add(
                per_component_bound
                    .checked_mul(interleaving_width)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
            )
            .and_then(|count| count.checked_add(final_interleaved_reencoding_bound))
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
    }
}

fn canonical_evaluation_point_field_operation_count(
    geometry: CanonicalReedSolomonGeometry,
) -> Result<u128, CanonicalReedSolomonError> {
    let logarithmic_block_length = geometry.block_length().ilog2();
    let root_exponent = 1_u64
        .checked_shl(GOLDILOCKS_TWO_ADICITY - logarithmic_block_length)
        .ok_or(CanonicalReedSolomonError::InvalidGeometry)?;
    counted_power_field_operation_count(root_exponent)?
        .checked_add(
            u128::try_from(geometry.block_length())
                .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?,
        )
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
}

fn counted_power_field_operation_count(
    mut exponent: u64,
) -> Result<u128, CanonicalReedSolomonError> {
    let mut operation_count = 0_u128;
    while exponent != 0 {
        if exponent & 1 == 1 {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        }
        exponent >>= 1;
        if exponent != 0 {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        }
    }
    Ok(operation_count)
}

fn canonical_horner_field_operation_count(
    block_length: usize,
    interleaving_width: usize,
    dimension: usize,
) -> Result<u128, CanonicalReedSolomonError> {
    u128::try_from(block_length)
        .ok()
        .and_then(|block_length| block_length.checked_mul(u128::try_from(interleaving_width).ok()?))
        .and_then(|count| count.checked_mul(u128::try_from(dimension).ok()?))
        .and_then(|count| count.checked_mul(2))
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
}

/// Worst case for the executable left-to-right reduced-row-echelon solver.
/// Every column has a pivot and every non-pivot row has a nonzero elimination
/// factor. Later pivots touch shorter row suffixes, which is reflected in the
/// triangular suffix sum rather than a dense rectangular overestimate.
fn canonical_linear_system_field_operation_bound(
    row_count: u128,
    unknown_count: u128,
) -> Result<u128, CanonicalReedSolomonError> {
    if row_count == 0 || unknown_count == 0 || unknown_count > row_count {
        return Err(CanonicalReedSolomonError::InvalidGeometry);
    }
    let affected_suffix_length_sum = unknown_count
        .checked_mul(
            unknown_count
                .checked_add(3)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
        )
        .and_then(|count| count.checked_div(2))
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
    let per_suffix_multiplier = row_count
        .checked_mul(2)
        .and_then(|count| count.checked_sub(1))
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
    unknown_count
        .checked_add(
            per_suffix_multiplier
                .checked_mul(affected_suffix_length_sum)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?,
        )
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalReedSolomonDecodedWitness {
    message_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    hiding_randomness_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    canonical_codeword_rows: Vec<Vec<ProofChallengeExtensionElement>>,
    field_operation_count: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CanonicalReedSolomonEncodedRows {
    rows: Vec<Vec<ProofChallengeExtensionElement>>,
    field_operation_count: u128,
}

impl CanonicalReedSolomonEncodedRows {
    pub(super) fn rows(&self) -> &[Vec<ProofChallengeExtensionElement>] {
        &self.rows
    }

    pub(super) const fn field_operation_count(&self) -> u128 {
        self.field_operation_count
    }
}

impl CanonicalReedSolomonDecodedWitness {
    pub(super) fn message_columns(&self) -> &[Vec<ProofChallengeExtensionElement>] {
        &self.message_columns
    }

    pub(super) fn hiding_randomness_columns(&self) -> &[Vec<ProofChallengeExtensionElement>] {
        &self.hiding_randomness_columns
    }

    pub(super) fn canonical_codeword_rows(&self) -> &[Vec<ProofChallengeExtensionElement>] {
        &self.canonical_codeword_rows
    }

    pub(super) const fn field_operation_count(&self) -> u128 {
        self.field_operation_count
    }
}

#[derive(Default)]
struct FieldOperationCounter {
    count: u128,
}

impl FieldOperationCounter {
    fn record(&mut self, operation_count: u128) -> Result<(), CanonicalReedSolomonError> {
        self.count = self
            .count
            .checked_add(operation_count)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        Ok(())
    }

    fn add(
        &mut self,
        left: ProofChallengeExtensionElement,
        right: ProofChallengeExtensionElement,
    ) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
        self.record(1)?;
        Ok(left.add(right))
    }

    fn subtract(
        &mut self,
        left: ProofChallengeExtensionElement,
        right: ProofChallengeExtensionElement,
    ) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
        self.record(1)?;
        Ok(left.subtract(right))
    }

    fn multiply(
        &mut self,
        left: ProofChallengeExtensionElement,
        right: ProofChallengeExtensionElement,
    ) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
        self.record(1)?;
        Ok(left.multiply(right))
    }

    fn inverse(
        &mut self,
        value: ProofChallengeExtensionElement,
    ) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
        self.record(1)?;
        value
            .inverse()
            .map_err(|_| CanonicalReedSolomonError::InconsistentLinearSystem)
    }
}

pub(super) fn encode_canonical_interleaved_reed_solomon(
    geometry: CanonicalReedSolomonGeometry,
    coefficient_columns: &[Vec<ProofChallengeExtensionElement>],
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CanonicalReedSolomonError> {
    Ok(
        encode_canonical_interleaved_reed_solomon_with_operation_count(
            geometry,
            coefficient_columns,
        )?
        .rows,
    )
}

pub(super) fn encode_canonical_interleaved_reed_solomon_with_operation_count(
    geometry: CanonicalReedSolomonGeometry,
    coefficient_columns: &[Vec<ProofChallengeExtensionElement>],
) -> Result<CanonicalReedSolomonEncodedRows, CanonicalReedSolomonError> {
    if coefficient_columns.len() != geometry.interleaving_width()
        || coefficient_columns
            .iter()
            .any(|column| column.len() != geometry.dimension())
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }
    let mut operation_counter = FieldOperationCounter::default();
    let evaluation_points = canonical_evaluation_points(geometry, &mut operation_counter)?;
    let rows = encode_coefficient_columns(
        geometry,
        coefficient_columns,
        &evaluation_points,
        &mut operation_counter,
    )?;
    Ok(CanonicalReedSolomonEncodedRows {
        rows,
        field_operation_count: operation_counter.count,
    })
}

pub(super) fn decode_canonical_interleaved_reed_solomon(
    geometry: CanonicalReedSolomonGeometry,
    received_rows: &[Vec<ProofChallengeExtensionElement>],
) -> Result<CanonicalReedSolomonDecodedWitness, CanonicalReedSolomonError> {
    if received_rows.len() != geometry.block_length()
        || received_rows
            .iter()
            .any(|row| row.len() != geometry.interleaving_width())
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }

    let mut operation_counter = FieldOperationCounter::default();
    let evaluation_points = canonical_evaluation_points(geometry, &mut operation_counter)?;
    let mut coefficient_columns = Vec::new();
    coefficient_columns
        .try_reserve_exact(geometry.interleaving_width())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    for component_ordinal in 0..geometry.interleaving_width() {
        let received_column = received_rows
            .iter()
            .map(|row| row[component_ordinal])
            .collect::<Vec<_>>();
        coefficient_columns.push(decode_coefficient_column(
            geometry,
            &evaluation_points,
            &received_column,
            &mut operation_counter,
        )?);
    }

    let canonical_codeword_rows = encode_coefficient_columns(
        geometry,
        &coefficient_columns,
        &evaluation_points,
        &mut operation_counter,
    )?;
    let differing_row_count = received_rows
        .iter()
        .zip(&canonical_codeword_rows)
        .filter(|(received, canonical)| received != canonical)
        .count();
    if differing_row_count > geometry.selected_decoding_error_count() {
        return Err(CanonicalReedSolomonError::OutsideDecodingRadius);
    }

    decoded_witness_from_coefficients(
        geometry,
        coefficient_columns,
        canonical_codeword_rows,
        operation_counter.count,
    )
}

/// Deterministically corrects erasures at every position outside
/// `retained_positions`.
///
/// Construction 7.2 uses this algorithm after forming the largest agreement
/// set between the revealed combined codeword and the two committed oracle
/// words. The retained positions are public, strictly increasing, and must
/// contain at least the complete `message || hiding randomness` dimension.
/// Every retained value is checked against the uniquely interpolated word;
/// values outside the set never enter the interpolation.
pub(super) fn correct_canonical_interleaved_reed_solomon_erasures(
    geometry: CanonicalReedSolomonGeometry,
    received_rows: &[Vec<ProofChallengeExtensionElement>],
    retained_positions: &[usize],
) -> Result<CanonicalReedSolomonDecodedWitness, CanonicalReedSolomonError> {
    if retained_positions.len() < geometry.dimension() {
        return Err(CanonicalReedSolomonError::OutsideDecodingRadius);
    }
    if received_rows.len() != geometry.block_length()
        || received_rows
            .iter()
            .any(|row| row.len() != geometry.interleaving_width())
        || retained_positions
            .windows(2)
            .any(|positions| positions[0] >= positions[1])
        || retained_positions
            .last()
            .is_some_and(|position| *position >= geometry.block_length())
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }

    let mut operation_counter = FieldOperationCounter::default();
    let evaluation_points = canonical_evaluation_points(geometry, &mut operation_counter)?;
    let mut coefficient_columns = Vec::new();
    coefficient_columns
        .try_reserve_exact(geometry.interleaving_width())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    for component_ordinal in 0..geometry.interleaving_width() {
        let mut system = Vec::new();
        system
            .try_reserve_exact(retained_positions.len())
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        for &position in retained_positions {
            let evaluation_point = evaluation_points[position];
            let mut row = vec![
                ProofChallengeExtensionElement::ZERO;
                geometry
                    .dimension()
                    .checked_add(1)
                    .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?
            ];
            let mut power = ProofChallengeExtensionElement::ONE;
            for coefficient in &mut row[..geometry.dimension()] {
                *coefficient = power;
                power = operation_counter.multiply(power, evaluation_point)?;
            }
            row[geometry.dimension()] = received_rows[position][component_ordinal];
            system.push(row);
        }
        coefficient_columns.push(solve_canonical_linear_system(
            &mut system,
            geometry.dimension(),
            &mut operation_counter,
        )?);
    }

    let canonical_codeword_rows = encode_coefficient_columns(
        geometry,
        &coefficient_columns,
        &evaluation_points,
        &mut operation_counter,
    )?;
    if retained_positions
        .iter()
        .any(|position| received_rows[*position] != canonical_codeword_rows[*position])
    {
        return Err(CanonicalReedSolomonError::InconsistentLinearSystem);
    }
    decoded_witness_from_coefficients(
        geometry,
        coefficient_columns,
        canonical_codeword_rows,
        operation_counter.count,
    )
}

pub(super) fn canonical_reed_solomon_evaluation_points(
    geometry: CanonicalReedSolomonGeometry,
) -> Result<Vec<ProofChallengeExtensionElement>, CanonicalReedSolomonError> {
    canonical_evaluation_points(geometry, &mut FieldOperationCounter::default())
}

fn canonical_evaluation_points(
    geometry: CanonicalReedSolomonGeometry,
    operation_counter: &mut FieldOperationCounter,
) -> Result<Vec<ProofChallengeExtensionElement>, CanonicalReedSolomonError> {
    let logarithmic_block_length = geometry.block_length().ilog2();
    if logarithmic_block_length > GOLDILOCKS_TWO_ADICITY {
        return Err(CanonicalReedSolomonError::InvalidGeometry);
    }
    let maximum_generator = ProofChallengeExtensionElement::from_base(
        ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR)
            .map_err(|_| CanonicalReedSolomonError::InvalidGeometry)?,
    );
    let root_exponent = 1_u64
        .checked_shl(GOLDILOCKS_TWO_ADICITY - logarithmic_block_length)
        .ok_or(CanonicalReedSolomonError::InvalidGeometry)?;
    let root = counted_power(maximum_generator, root_exponent, operation_counter)?;
    let mut evaluation_points = Vec::new();
    evaluation_points
        .try_reserve_exact(geometry.block_length())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    let mut point = ProofChallengeExtensionElement::ONE;
    for _ in 0..geometry.block_length() {
        evaluation_points.push(point);
        point = operation_counter.multiply(point, root)?;
    }
    if point != ProofChallengeExtensionElement::ONE
        || (geometry.block_length() > 1
            && evaluation_points[geometry.block_length() / 2]
                == ProofChallengeExtensionElement::ONE)
    {
        return Err(CanonicalReedSolomonError::InvalidGeometry);
    }
    Ok(evaluation_points)
}

fn decoded_witness_from_coefficients(
    geometry: CanonicalReedSolomonGeometry,
    coefficient_columns: Vec<Vec<ProofChallengeExtensionElement>>,
    canonical_codeword_rows: Vec<Vec<ProofChallengeExtensionElement>>,
    field_operation_count: u128,
) -> Result<CanonicalReedSolomonDecodedWitness, CanonicalReedSolomonError> {
    if coefficient_columns.len() != geometry.interleaving_width()
        || coefficient_columns
            .iter()
            .any(|column| column.len() != geometry.dimension())
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }
    let hiding_randomness_end = geometry
        .message_length()
        .checked_add(geometry.hiding_randomness_length())
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
    let mut message_columns = Vec::new();
    let mut hiding_randomness_columns = Vec::new();
    message_columns
        .try_reserve_exact(geometry.interleaving_width())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    hiding_randomness_columns
        .try_reserve_exact(geometry.interleaving_width())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    for coefficients in coefficient_columns {
        message_columns.push(coefficients[..geometry.message_length()].to_vec());
        hiding_randomness_columns
            .push(coefficients[geometry.message_length()..hiding_randomness_end].to_vec());
    }
    Ok(CanonicalReedSolomonDecodedWitness {
        message_columns,
        hiding_randomness_columns,
        canonical_codeword_rows,
        field_operation_count,
    })
}

fn counted_power(
    value: ProofChallengeExtensionElement,
    mut exponent: u64,
    operation_counter: &mut FieldOperationCounter,
) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
    let mut result = ProofChallengeExtensionElement::ONE;
    let mut running_power = value;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = operation_counter.multiply(result, running_power)?;
        }
        exponent >>= 1;
        if exponent != 0 {
            running_power = operation_counter.multiply(running_power, running_power)?;
        }
    }
    Ok(result)
}

fn encode_coefficient_columns(
    geometry: CanonicalReedSolomonGeometry,
    coefficient_columns: &[Vec<ProofChallengeExtensionElement>],
    evaluation_points: &[ProofChallengeExtensionElement],
    operation_counter: &mut FieldOperationCounter,
) -> Result<Vec<Vec<ProofChallengeExtensionElement>>, CanonicalReedSolomonError> {
    if coefficient_columns.len() != geometry.interleaving_width()
        || coefficient_columns
            .iter()
            .any(|column| column.len() != geometry.dimension())
        || evaluation_points.len() != geometry.block_length()
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(geometry.block_length())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    for evaluation_point in evaluation_points {
        let mut row = Vec::new();
        row.try_reserve_exact(geometry.interleaving_width())
            .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
        for coefficients in coefficient_columns {
            row.push(evaluate_polynomial(
                coefficients,
                *evaluation_point,
                operation_counter,
            )?);
        }
        rows.push(row);
    }
    Ok(rows)
}

fn decode_coefficient_column(
    geometry: CanonicalReedSolomonGeometry,
    evaluation_points: &[ProofChallengeExtensionElement],
    received_values: &[ProofChallengeExtensionElement],
    operation_counter: &mut FieldOperationCounter,
) -> Result<Vec<ProofChallengeExtensionElement>, CanonicalReedSolomonError> {
    if evaluation_points.len() != geometry.block_length()
        || received_values.len() != geometry.block_length()
    {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }
    let dimension = geometry.dimension();
    let maximum_error_count = geometry.selected_decoding_error_count();
    let numerator_coefficient_count = dimension
        .checked_add(maximum_error_count)
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
    let unknown_count = numerator_coefficient_count
        .checked_add(maximum_error_count)
        .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
    if unknown_count >= geometry.block_length() {
        return Err(CanonicalReedSolomonError::InvalidGeometry);
    }

    let mut system = Vec::new();
    system
        .try_reserve_exact(geometry.block_length())
        .map_err(|_| CanonicalReedSolomonError::ArithmeticOverflow)?;
    for (evaluation_point, received_value) in evaluation_points.iter().zip(received_values) {
        let mut row = vec![ProofChallengeExtensionElement::ZERO; unknown_count + 1];
        let mut power = ProofChallengeExtensionElement::ONE;
        for coefficient in &mut row[..numerator_coefficient_count] {
            *coefficient = power;
            power = operation_counter.multiply(power, *evaluation_point)?;
        }
        let mut locator_power = ProofChallengeExtensionElement::ONE;
        for locator_coefficient_ordinal in 0..maximum_error_count {
            row[numerator_coefficient_count + locator_coefficient_ordinal] = operation_counter
                .multiply(*received_value, locator_power)?
                .negate();
            locator_power = operation_counter.multiply(locator_power, *evaluation_point)?;
        }
        let monic_locator_power = if maximum_error_count == 0 {
            ProofChallengeExtensionElement::ONE
        } else {
            locator_power
        };
        row[unknown_count] = operation_counter.multiply(*received_value, monic_locator_power)?;
        system.push(row);
    }

    let solution = solve_canonical_linear_system(&mut system, unknown_count, operation_counter)?;
    let numerator = solution[..numerator_coefficient_count].to_vec();
    let mut error_locator = solution[numerator_coefficient_count..].to_vec();
    error_locator.push(ProofChallengeExtensionElement::ONE);
    let message =
        divide_by_monic_error_locator(numerator, &error_locator, dimension, operation_counter)?;
    let canonical_values = evaluation_points
        .iter()
        .map(|evaluation_point| evaluate_polynomial(&message, *evaluation_point, operation_counter))
        .collect::<Result<Vec<_>, _>>()?;
    let differing_value_count = received_values
        .iter()
        .zip(&canonical_values)
        .filter(|(received, canonical)| received != canonical)
        .count();
    if differing_value_count > maximum_error_count {
        return Err(CanonicalReedSolomonError::OutsideDecodingRadius);
    }
    Ok(message)
}

fn solve_canonical_linear_system(
    rows: &mut [Vec<ProofChallengeExtensionElement>],
    unknown_count: usize,
    operation_counter: &mut FieldOperationCounter,
) -> Result<Vec<ProofChallengeExtensionElement>, CanonicalReedSolomonError> {
    if rows.is_empty() || rows.iter().any(|row| row.len() != unknown_count + 1) {
        return Err(CanonicalReedSolomonError::MalformedOracle);
    }
    let mut pivot_row_ordinal = 0_usize;
    let mut pivot_rows = vec![None; unknown_count];
    for column_ordinal in 0..unknown_count {
        let Some(nonzero_row_offset) = rows[pivot_row_ordinal..]
            .iter()
            .position(|row| row[column_ordinal] != ProofChallengeExtensionElement::ZERO)
        else {
            continue;
        };
        let selected_row_ordinal = pivot_row_ordinal
            .checked_add(nonzero_row_offset)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        rows.swap(pivot_row_ordinal, selected_row_ordinal);
        let pivot_inverse = operation_counter.inverse(rows[pivot_row_ordinal][column_ordinal])?;
        for value in &mut rows[pivot_row_ordinal][column_ordinal..=unknown_count] {
            *value = operation_counter.multiply(*value, pivot_inverse)?;
        }
        for row_ordinal in 0..rows.len() {
            if row_ordinal == pivot_row_ordinal {
                continue;
            }
            let elimination_factor = rows[row_ordinal][column_ordinal];
            if elimination_factor == ProofChallengeExtensionElement::ZERO {
                continue;
            }
            for affected_column_ordinal in column_ordinal..=unknown_count {
                let scaled_pivot = operation_counter.multiply(
                    elimination_factor,
                    rows[pivot_row_ordinal][affected_column_ordinal],
                )?;
                rows[row_ordinal][affected_column_ordinal] = operation_counter
                    .subtract(rows[row_ordinal][affected_column_ordinal], scaled_pivot)?;
            }
        }
        pivot_rows[column_ordinal] = Some(pivot_row_ordinal);
        pivot_row_ordinal += 1;
        if pivot_row_ordinal == rows.len() {
            break;
        }
    }
    if rows.iter().any(|row| {
        row[..unknown_count]
            .iter()
            .all(|coefficient| *coefficient == ProofChallengeExtensionElement::ZERO)
            && row[unknown_count] != ProofChallengeExtensionElement::ZERO
    }) {
        return Err(CanonicalReedSolomonError::InconsistentLinearSystem);
    }
    let mut solution = vec![ProofChallengeExtensionElement::ZERO; unknown_count];
    for (column_ordinal, row_ordinal) in pivot_rows.into_iter().enumerate() {
        if let Some(row_ordinal) = row_ordinal {
            solution[column_ordinal] = rows[row_ordinal][unknown_count];
        }
    }
    Ok(solution)
}

fn divide_by_monic_error_locator(
    mut numerator: Vec<ProofChallengeExtensionElement>,
    error_locator: &[ProofChallengeExtensionElement],
    expected_quotient_length: usize,
    operation_counter: &mut FieldOperationCounter,
) -> Result<Vec<ProofChallengeExtensionElement>, CanonicalReedSolomonError> {
    let error_locator_degree = error_locator
        .len()
        .checked_sub(1)
        .ok_or(CanonicalReedSolomonError::NonCodewordQuotient)?;
    if error_locator.last() != Some(&ProofChallengeExtensionElement::ONE)
        || numerator.len()
            != expected_quotient_length
                .checked_add(error_locator_degree)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?
    {
        return Err(CanonicalReedSolomonError::NonCodewordQuotient);
    }
    let mut quotient = vec![ProofChallengeExtensionElement::ZERO; expected_quotient_length];
    for quotient_ordinal in (0..expected_quotient_length).rev() {
        let numerator_ordinal = quotient_ordinal
            .checked_add(error_locator_degree)
            .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
        let quotient_coefficient = numerator[numerator_ordinal];
        quotient[quotient_ordinal] = quotient_coefficient;
        for (locator_ordinal, locator_coefficient) in error_locator.iter().enumerate() {
            let product = operation_counter.multiply(quotient_coefficient, *locator_coefficient)?;
            let destination_ordinal = quotient_ordinal
                .checked_add(locator_ordinal)
                .ok_or(CanonicalReedSolomonError::ArithmeticOverflow)?;
            numerator[destination_ordinal] =
                operation_counter.subtract(numerator[destination_ordinal], product)?;
        }
    }
    if numerator
        .iter()
        .any(|coefficient| *coefficient != ProofChallengeExtensionElement::ZERO)
    {
        return Err(CanonicalReedSolomonError::NonCodewordQuotient);
    }
    Ok(quotient)
}

fn evaluate_polynomial(
    coefficients: &[ProofChallengeExtensionElement],
    point: ProofChallengeExtensionElement,
    operation_counter: &mut FieldOperationCounter,
) -> Result<ProofChallengeExtensionElement, CanonicalReedSolomonError> {
    let mut value = ProofChallengeExtensionElement::ZERO;
    for coefficient in coefficients.iter().rev() {
        value = operation_counter.multiply(value, point)?;
        value = operation_counter.add(value, *coefficient)?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u64) -> ProofChallengeExtensionElement {
        ProofChallengeExtensionElement::from_base(
            ProofBaseFieldElement::from_canonical(value).expect("small canonical field element"),
        )
    }

    fn geometry() -> CanonicalReedSolomonGeometry {
        CanonicalReedSolomonGeometry::new(2, 1, 8, 3)
            .expect("the small interleaved code geometry is valid")
    }

    fn coefficient_columns() -> Vec<Vec<ProofChallengeExtensionElement>> {
        vec![
            vec![field(3), field(5), field(7)],
            vec![field(11), field(13), field(17)],
            vec![field(19), field(23), field(29)],
        ]
    }

    fn assert_decodes_to_original(received_rows: &[Vec<ProofChallengeExtensionElement>]) {
        let decoded = decode_canonical_interleaved_reed_solomon(geometry(), received_rows)
            .expect("the oracle is within the unique-decoding radius");
        let coefficients = coefficient_columns();
        assert_eq!(
            decoded.message_columns(),
            coefficients
                .iter()
                .map(|column| column[..2].to_vec())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.hiding_randomness_columns(),
            coefficients
                .iter()
                .map(|column| column[2..].to_vec())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            decoded.canonical_codeword_rows(),
            encode_canonical_interleaved_reed_solomon(geometry(), &coefficients)
                .expect("the original coefficients encode")
        );
        assert!(decoded.field_operation_count() > 0);
        assert!(
            decoded.field_operation_count()
                <= geometry()
                    .decoding_field_operation_bound()
                    .expect("the decoder operation bound derives")
        );
    }

    #[test]
    fn canonical_operation_bounds_cover_every_executable_correction_path() {
        let encoded = encode_canonical_interleaved_reed_solomon_with_operation_count(
            geometry(),
            &coefficient_columns(),
        )
        .expect("the canonical rows encode with an operation count");
        assert_eq!(
            encoded.field_operation_count(),
            geometry()
                .encoding_field_operation_count()
                .expect("the exact encoder operation count derives")
        );

        for retained_positions in [vec![0, 1, 2], vec![0, 2, 4, 6], (0..8).collect()] {
            let corrected = correct_canonical_interleaved_reed_solomon_erasures(
                geometry(),
                encoded.rows(),
                &retained_positions,
            )
            .expect("the retained positions determine the original codeword");
            assert!(
                corrected.field_operation_count()
                    <= geometry()
                        .erasure_correction_field_operation_bound(retained_positions.len())
                        .expect("the erasure-correction operation bound derives")
            );
        }
    }

    #[test]
    fn canonical_decoder_recovers_zero_one_and_maximum_shared_row_errors() {
        let canonical_rows =
            encode_canonical_interleaved_reed_solomon(geometry(), &coefficient_columns())
                .expect("the canonical rows encode");
        assert_decodes_to_original(&canonical_rows);

        let mut one_error = canonical_rows.clone();
        one_error[7][1] = one_error[7][1].add(field(31));
        assert_decodes_to_original(&one_error);

        let mut maximum_errors = canonical_rows;
        maximum_errors[0][0] = maximum_errors[0][0].add(field(37));
        maximum_errors[0][2] = maximum_errors[0][2].add(field(41));
        maximum_errors[6][1] = maximum_errors[6][1].add(field(43));
        assert_decodes_to_original(&maximum_errors);
    }

    #[test]
    fn canonical_decoder_refuses_excess_union_errors_and_malformed_rows() {
        let canonical_rows =
            encode_canonical_interleaved_reed_solomon(geometry(), &coefficient_columns())
                .expect("the canonical rows encode");
        let mut excess_union_errors = canonical_rows.clone();
        excess_union_errors[0][0] = excess_union_errors[0][0].add(field(1));
        excess_union_errors[3][1] = excess_union_errors[3][1].add(field(1));
        excess_union_errors[6][2] = excess_union_errors[6][2].add(field(1));
        assert!(matches!(
            decode_canonical_interleaved_reed_solomon(geometry(), &excess_union_errors),
            Err(CanonicalReedSolomonError::InconsistentLinearSystem
                | CanonicalReedSolomonError::NonCodewordQuotient
                | CanonicalReedSolomonError::OutsideDecodingRadius)
        ));

        assert_eq!(
            decode_canonical_interleaved_reed_solomon(geometry(), &canonical_rows[..7]),
            Err(CanonicalReedSolomonError::MalformedOracle)
        );
        let mut wrong_width = canonical_rows;
        wrong_width[4].pop();
        assert_eq!(
            decode_canonical_interleaved_reed_solomon(geometry(), &wrong_width),
            Err(CanonicalReedSolomonError::MalformedOracle)
        );
    }

    #[test]
    fn canonical_erasure_corrector_uses_only_the_retained_agreement_set() {
        let canonical_rows =
            encode_canonical_interleaved_reed_solomon(geometry(), &coefficient_columns())
                .expect("the canonical rows encode");
        let retained_positions = vec![0, 2, 4, 6];
        let mut changed_erased_rows = canonical_rows.clone();
        for position in [1_usize, 3, 5, 7] {
            for component_ordinal in 0..geometry().interleaving_width() {
                changed_erased_rows[position][component_ordinal] =
                    changed_erased_rows[position][component_ordinal].add(field(
                        31 + u64::try_from(position + component_ordinal).unwrap(),
                    ));
            }
        }
        let corrected = correct_canonical_interleaved_reed_solomon_erasures(
            geometry(),
            &changed_erased_rows,
            &retained_positions,
        )
        .expect("four retained positions determine the dimension-three word");
        assert_eq!(corrected.canonical_codeword_rows(), canonical_rows);
        assert!(corrected.field_operation_count() > 0);

        let mut inconsistent_retained_rows = changed_erased_rows;
        inconsistent_retained_rows[6][2] = inconsistent_retained_rows[6][2].add(field(1));
        assert_eq!(
            correct_canonical_interleaved_reed_solomon_erasures(
                geometry(),
                &inconsistent_retained_rows,
                &retained_positions,
            ),
            Err(CanonicalReedSolomonError::InconsistentLinearSystem)
        );
    }

    #[test]
    fn canonical_erasure_corrector_refuses_short_duplicate_and_unsorted_sets() {
        let canonical_rows =
            encode_canonical_interleaved_reed_solomon(geometry(), &coefficient_columns())
                .expect("the canonical rows encode");
        assert_eq!(
            correct_canonical_interleaved_reed_solomon_erasures(
                geometry(),
                &canonical_rows,
                &[0, 1],
            ),
            Err(CanonicalReedSolomonError::OutsideDecodingRadius)
        );
        for retained_positions in [vec![0, 2, 2], vec![0, 4, 2]] {
            assert_eq!(
                correct_canonical_interleaved_reed_solomon_erasures(
                    geometry(),
                    &canonical_rows,
                    &retained_positions,
                ),
                Err(CanonicalReedSolomonError::MalformedOracle)
            );
        }
    }

    #[test]
    fn canonical_geometry_refuses_non_power_of_two_and_degenerate_codes() {
        assert_eq!(
            CanonicalReedSolomonGeometry::new(2, 1, 7, 1),
            Err(CanonicalReedSolomonError::InvalidGeometry)
        );
        assert_eq!(
            CanonicalReedSolomonGeometry::new(2, 0, 8, 1),
            Err(CanonicalReedSolomonError::InvalidGeometry)
        );
        assert_eq!(
            CanonicalReedSolomonGeometry::new(7, 1, 8, 1),
            Err(CanonicalReedSolomonError::InvalidGeometry)
        );
        assert_eq!(
            CanonicalReedSolomonGeometry::new(2, 1, 8, 0),
            Err(CanonicalReedSolomonError::InvalidGeometry)
        );
    }
}
