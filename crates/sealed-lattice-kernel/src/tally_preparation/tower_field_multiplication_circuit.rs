use super::{
    BinaryFieldElement256, TallyPreparationError,
    binary_linear_circuit::CompiledBinaryLinearCircuit,
};

const CANONICAL_FIELD_BIT_LENGTH: usize =
    BinaryFieldElement256::CANONICAL_BYTE_LENGTH * u8::BITS as usize;
const SUBFIELD_BIT_LENGTH: usize = 8;
const TOWER_EXTENSION_DEGREE: usize = CANONICAL_FIELD_BIT_LENGTH / SUBFIELD_BIT_LENGTH;
const EVALUATION_POINT_COUNT: usize = TOWER_EXTENSION_DEGREE * 2 - 1;
const SUBFIELD_KARATSUBA_TERM_COUNT: usize = 27;
const TOWER_FIELD_MULTIPLICATION_CONJUNCTION_COUNT: u64 = 1_701;
const DIRECT_TOWER_FIELD_MULTIPLICATION_EXCLUSIVE_OR_COUNT: u64 = 648_034;
const WINDOWED_TOWER_FIELD_MULTIPLICATION_EXCLUSIVE_OR_COUNT: u64 = 198_048;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct BinaryLinearMask256 {
    limbs: [u64; 4],
}

impl BinaryLinearMask256 {
    const ZERO: Self = Self { limbs: [0_u64; 4] };

    fn from_field_element(element: BinaryFieldElement256) -> Self {
        let canonical_bytes = element.canonical_bytes();
        let mut limbs = [0_u64; 4];
        for (limb, limb_bytes) in limbs.iter_mut().zip(canonical_bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(
                limb_bytes
                    .try_into()
                    .expect("an exact eight-byte chunk must convert to a limb"),
            );
        }
        Self { limbs }
    }

    fn identity(bit_position: usize) -> Result<Self, TallyPreparationError> {
        if bit_position >= CANONICAL_FIELD_BIT_LENGTH {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mut mask = Self::ZERO;
        mask.set(bit_position);
        Ok(mask)
    }

    fn bit(self, bit_position: usize) -> Result<bool, TallyPreparationError> {
        if bit_position >= CANONICAL_FIELD_BIT_LENGTH {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        Ok((self.limbs[bit_position / 64] >> (bit_position % 64)) & 1_u64 == 1_u64)
    }

    fn set(&mut self, bit_position: usize) {
        self.limbs[bit_position / 64] |= 1_u64 << (bit_position % 64);
    }

    fn exclusive_or(self, other: Self) -> Self {
        Self {
            limbs: core::array::from_fn(|limb_position| {
                self.limbs[limb_position] ^ other.limbs[limb_position]
            }),
        }
    }

    fn hamming_weight(self) -> u64 {
        self.limbs
            .iter()
            .map(|limb| u64::from(limb.count_ones()))
            .sum()
    }

    fn parity(self, element: BinaryFieldElement256) -> bool {
        let element_mask = Self::from_field_element(element);
        self.limbs
            .iter()
            .zip(element_mask.limbs)
            .fold(0_u32, |parity, (mask_limb, element_limb)| {
                parity ^ (mask_limb & element_limb).count_ones()
            })
            & 1_u32
            == 1_u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SubfieldBilinearTerm {
    left_mask: u8,
    right_mask: u8,
    raw_output_coefficients: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalFieldBilinearTerm {
    left_mask: BinaryLinearMask256,
    right_mask: BinaryLinearMask256,
    output: BinaryFieldElement256,
}

/// Executable low-conjunction circuit for the canonical binary-field product.
///
/// The circuit views `GF(2^256)` as a degree-32 extension of its unique
/// `GF(2^8)` subfield. It evaluates both degree-31 tower polynomials at 63
/// distinct subfield points, uses a 27-conjunction Karatsuba product for each
/// pair of eight-bit values, and interpolates the degree-62 product at the
/// canonical polynomial generator. All basis changes, evaluations, and
/// interpolation maps are binary linear maps.
///
/// This is an unactivated research comparison owner. It does not replace the
/// scalar field implementation or select an MPC realization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledTowerFieldMultiplicationCircuit {
    terms: Vec<CanonicalFieldBilinearTerm>,
    distinct_input_masks: Vec<BinaryLinearMask256>,
    term_input_linear_form_positions: Vec<(usize, usize)>,
    input_linear_circuit: CompiledBinaryLinearCircuit,
    output_linear_circuit: CompiledBinaryLinearCircuit,
    exclusive_or_count: u64,
}

impl CompiledTowerFieldMultiplicationCircuit {
    pub(crate) fn compile() -> Result<Self, TallyPreparationError> {
        let subfield_generator = find_subfield_generator()?;
        let subfield_power_basis = field_power_basis(subfield_generator, SUBFIELD_BIT_LENGTH);
        let tower_generator = BinaryFieldElement256::from_low_polynomial_u16(2);
        let tower_power_basis = field_power_basis(tower_generator, TOWER_EXTENSION_DEGREE);
        let tower_basis = tower_basis(&subfield_power_basis, &tower_power_basis)?;
        let canonical_to_tower_rows = invert_binary_basis(&tower_basis)?;
        let evaluation_points = evaluation_points(&subfield_power_basis)?;
        let lagrange_coefficients = lagrange_coefficients(&evaluation_points, tower_generator)?;
        verify_lagrange_coefficients(&evaluation_points, &lagrange_coefficients, tower_generator)?;
        let subfield_terms = subfield_karatsuba_terms();
        if subfield_terms.len() != SUBFIELD_KARATSUBA_TERM_COUNT {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        let mut terms = Vec::with_capacity(
            EVALUATION_POINT_COUNT
                .checked_mul(SUBFIELD_KARATSUBA_TERM_COUNT)
                .ok_or(TallyPreparationError::ArithmeticOverflow)?,
        );
        for (evaluation_point, lagrange_coefficient) in evaluation_points
            .iter()
            .copied()
            .zip(lagrange_coefficients.iter().copied())
        {
            let evaluation_masks = evaluation_masks(
                evaluation_point,
                &subfield_power_basis,
                &canonical_to_tower_rows,
            )?;
            for subfield_term in &subfield_terms {
                let subfield_output = reduce_subfield_raw_output(
                    subfield_term.raw_output_coefficients,
                    &subfield_power_basis,
                    &canonical_to_tower_rows,
                )?;
                let output = lagrange_coefficient.multiply(subfield_output);
                if output.is_zero() {
                    return Err(TallyPreparationError::GeometryMismatch);
                }
                terms.push(CanonicalFieldBilinearTerm {
                    left_mask: combine_evaluation_masks(&evaluation_masks, subfield_term.left_mask),
                    right_mask: combine_evaluation_masks(
                        &evaluation_masks,
                        subfield_term.right_mask,
                    ),
                    output,
                });
            }
        }

        let expected_term_count = EVALUATION_POINT_COUNT
            .checked_mul(SUBFIELD_KARATSUBA_TERM_COUNT)
            .ok_or(TallyPreparationError::ArithmeticOverflow)?;
        if terms.len() != expected_term_count {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let distinct_input_masks = distinct_input_masks(&terms);
        if distinct_input_masks
            .iter()
            .any(|input_mask| input_mask.hamming_weight() == 0)
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let direct_exclusive_or_count =
            exact_straight_line_exclusive_or_count(&terms, &distinct_input_masks)?;
        if terms.len() as u64 != TOWER_FIELD_MULTIPLICATION_CONJUNCTION_COUNT
            || direct_exclusive_or_count != DIRECT_TOWER_FIELD_MULTIPLICATION_EXCLUSIVE_OR_COUNT
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let term_input_linear_form_positions = terms
            .iter()
            .map(|term| {
                Ok((
                    distinct_input_masks
                        .binary_search(&term.left_mask)
                        .map_err(|_| TallyPreparationError::GeometryMismatch)?,
                    distinct_input_masks
                        .binary_search(&term.right_mask)
                        .map_err(|_| TallyPreparationError::GeometryMismatch)?,
                ))
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;
        let input_targets = distinct_input_masks
            .iter()
            .copied()
            .map(|input_mask| binary_target(input_mask, CANONICAL_FIELD_BIT_LENGTH))
            .collect::<Result<Vec<_>, _>>()?;
        let input_linear_circuit = CompiledBinaryLinearCircuit::compile_smallest_windowed(
            &input_targets,
            CANONICAL_FIELD_BIT_LENGTH,
        )?;
        let output_targets = output_targets(&terms)?;
        let output_linear_circuit =
            CompiledBinaryLinearCircuit::compile_smallest_windowed(&output_targets, terms.len())?;
        let exclusive_or_count = checked_add(
            checked_multiply(input_linear_circuit.operation_count(), 2)?,
            output_linear_circuit.operation_count(),
        )?;
        if exclusive_or_count != WINDOWED_TOWER_FIELD_MULTIPLICATION_EXCLUSIVE_OR_COUNT
            || exclusive_or_count >= direct_exclusive_or_count
        {
            return Err(TallyPreparationError::GeometryMismatch);
        }

        Ok(Self {
            terms,
            distinct_input_masks,
            term_input_linear_form_positions,
            input_linear_circuit,
            output_linear_circuit,
            exclusive_or_count,
        })
    }

    pub(crate) fn conjunction_count(&self) -> u64 {
        self.terms.len() as u64
    }

    pub(crate) fn exclusive_or_count(&self) -> u64 {
        self.exclusive_or_count
    }

    pub(crate) fn distinct_input_linear_form_count(&self) -> u64 {
        self.distinct_input_masks.len() as u64
    }

    pub(crate) fn input_linear_window_width(&self) -> u64 {
        self.input_linear_circuit.window_width()
    }

    pub(crate) fn output_linear_window_width(&self) -> u64 {
        self.output_linear_circuit.window_width()
    }

    pub(crate) fn multiply(
        &self,
        left: BinaryFieldElement256,
        right: BinaryFieldElement256,
    ) -> Result<BinaryFieldElement256, TallyPreparationError> {
        let left_linear_forms = self.input_linear_circuit.evaluate(&canonical_bits(left))?;
        let right_linear_forms = self.input_linear_circuit.evaluate(&canonical_bits(right))?;
        let conjunction_values = self
            .term_input_linear_form_positions
            .iter()
            .map(|(left_position, right_position)| {
                Ok(*left_linear_forms
                    .get(*left_position)
                    .ok_or(TallyPreparationError::GeometryMismatch)?
                    & *right_linear_forms
                        .get(*right_position)
                        .ok_or(TallyPreparationError::GeometryMismatch)?)
            })
            .collect::<Result<Vec<_>, TallyPreparationError>>()?;
        let output_bits = self.output_linear_circuit.evaluate(&conjunction_values)?;
        if output_bits.len() != CANONICAL_FIELD_BIT_LENGTH {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        let mut output_bytes = [0_u8; BinaryFieldElement256::CANONICAL_BYTE_LENGTH];
        for (output_bit_position, output_bit) in output_bits.iter().copied().enumerate() {
            if output_bit {
                output_bytes[output_bit_position / u8::BITS as usize] |=
                    1_u8 << (output_bit_position % u8::BITS as usize);
            }
        }
        BinaryFieldElement256::from_canonical_bytes(&output_bytes)
    }
}

pub(crate) fn tower_field_multiplication_conjunction_count() -> u64 {
    TOWER_FIELD_MULTIPLICATION_CONJUNCTION_COUNT
}

pub(crate) fn tower_field_multiplication_exclusive_or_count() -> u64 {
    WINDOWED_TOWER_FIELD_MULTIPLICATION_EXCLUSIVE_OR_COUNT
}

fn find_subfield_generator() -> Result<BinaryFieldElement256, TallyPreparationError> {
    for candidate_value in 2_u16..=u16::MAX {
        let candidate = BinaryFieldElement256::from_low_polynomial_u16(candidate_value);
        let projected_candidate = project_to_subfield(candidate);
        if projected_candidate.is_zero()
            || frobenius_power(projected_candidate, SUBFIELD_BIT_LENGTH) != projected_candidate
        {
            continue;
        }
        let power_basis = field_power_basis(projected_candidate, SUBFIELD_BIT_LENGTH);
        if binary_vector_rank(
            &power_basis
                .iter()
                .copied()
                .map(BinaryLinearMask256::from_field_element)
                .collect::<Vec<_>>(),
        ) == SUBFIELD_BIT_LENGTH
        {
            return Ok(projected_candidate);
        }
    }
    Err(TallyPreparationError::GeometryMismatch)
}

fn project_to_subfield(candidate: BinaryFieldElement256) -> BinaryFieldElement256 {
    let mut projected_candidate = BinaryFieldElement256::ONE;
    let mut conjugate = candidate;
    for _conjugate_position in 0..TOWER_EXTENSION_DEGREE {
        projected_candidate = projected_candidate.multiply(conjugate);
        conjugate = frobenius_power(conjugate, SUBFIELD_BIT_LENGTH);
    }
    projected_candidate
}

fn frobenius_power(
    mut element: BinaryFieldElement256,
    repeated_square_count: usize,
) -> BinaryFieldElement256 {
    for _square_position in 0..repeated_square_count {
        element = element.square();
    }
    element
}

fn field_power_basis(
    generator: BinaryFieldElement256,
    basis_length: usize,
) -> Vec<BinaryFieldElement256> {
    let mut basis = Vec::with_capacity(basis_length);
    let mut power = BinaryFieldElement256::ONE;
    for _basis_position in 0..basis_length {
        basis.push(power);
        power = power.multiply(generator);
    }
    basis
}

fn tower_basis(
    subfield_power_basis: &[BinaryFieldElement256],
    tower_power_basis: &[BinaryFieldElement256],
) -> Result<Vec<BinaryFieldElement256>, TallyPreparationError> {
    if subfield_power_basis.len() != SUBFIELD_BIT_LENGTH
        || tower_power_basis.len() != TOWER_EXTENSION_DEGREE
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let mut basis = Vec::with_capacity(CANONICAL_FIELD_BIT_LENGTH);
    for tower_power in tower_power_basis {
        for subfield_power in subfield_power_basis {
            basis.push(tower_power.multiply(*subfield_power));
        }
    }
    Ok(basis)
}

fn invert_binary_basis(
    basis_columns: &[BinaryFieldElement256],
) -> Result<Vec<BinaryLinearMask256>, TallyPreparationError> {
    if basis_columns.len() != CANONICAL_FIELD_BIT_LENGTH {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let basis_column_masks = basis_columns
        .iter()
        .copied()
        .map(BinaryLinearMask256::from_field_element)
        .collect::<Vec<_>>();
    let mut matrix_rows = vec![BinaryLinearMask256::ZERO; CANONICAL_FIELD_BIT_LENGTH];
    let mut inverse_rows = (0..CANONICAL_FIELD_BIT_LENGTH)
        .map(BinaryLinearMask256::identity)
        .collect::<Result<Vec<_>, _>>()?;
    for (row_position, matrix_row) in matrix_rows.iter_mut().enumerate() {
        for (column_position, basis_column) in basis_column_masks.iter().copied().enumerate() {
            if basis_column.bit(row_position)? {
                matrix_row.set(column_position);
            }
        }
    }

    for pivot_position in 0..CANONICAL_FIELD_BIT_LENGTH {
        let pivot_row = (pivot_position..CANONICAL_FIELD_BIT_LENGTH)
            .find(|row_position| {
                matrix_rows[*row_position]
                    .bit(pivot_position)
                    .expect("matrix positions are within the fixed field width")
            })
            .ok_or(TallyPreparationError::GeometryMismatch)?;
        matrix_rows.swap(pivot_position, pivot_row);
        inverse_rows.swap(pivot_position, pivot_row);

        for row_position in 0..CANONICAL_FIELD_BIT_LENGTH {
            if row_position != pivot_position && matrix_rows[row_position].bit(pivot_position)? {
                matrix_rows[row_position] =
                    matrix_rows[row_position].exclusive_or(matrix_rows[pivot_position]);
                inverse_rows[row_position] =
                    inverse_rows[row_position].exclusive_or(inverse_rows[pivot_position]);
            }
        }
    }
    for (row_position, matrix_row) in matrix_rows.iter().copied().enumerate() {
        if matrix_row != BinaryLinearMask256::identity(row_position)? {
            return Err(TallyPreparationError::GeometryMismatch);
        }
    }
    Ok(inverse_rows)
}

fn binary_vector_rank(vectors: &[BinaryLinearMask256]) -> usize {
    let mut rows = vectors.to_vec();
    let mut rank = 0_usize;
    for bit_position in 0..CANONICAL_FIELD_BIT_LENGTH {
        let Some(pivot_row) = (rank..rows.len()).find(|row_position| {
            rows[*row_position]
                .bit(bit_position)
                .expect("rank positions are within the fixed field width")
        }) else {
            continue;
        };
        rows.swap(rank, pivot_row);
        for row_position in 0..rows.len() {
            if row_position != rank
                && rows[row_position]
                    .bit(bit_position)
                    .expect("rank positions are within the fixed field width")
            {
                rows[row_position] = rows[row_position].exclusive_or(rows[rank]);
            }
        }
        rank += 1;
        if rank == rows.len() {
            break;
        }
    }
    rank
}

fn evaluation_points(
    subfield_power_basis: &[BinaryFieldElement256],
) -> Result<Vec<BinaryFieldElement256>, TallyPreparationError> {
    if subfield_power_basis.len() != SUBFIELD_BIT_LENGTH {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    (0_u8..EVALUATION_POINT_COUNT as u8)
        .map(|coordinates| embed_subfield_coordinates(coordinates, subfield_power_basis))
        .collect()
}

fn embed_subfield_coordinates(
    coordinates: u8,
    subfield_power_basis: &[BinaryFieldElement256],
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    if subfield_power_basis.len() != SUBFIELD_BIT_LENGTH {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(subfield_power_basis.iter().copied().enumerate().fold(
        BinaryFieldElement256::ZERO,
        |element, (coordinate_position, basis_element)| {
            if (coordinates >> coordinate_position) & 1_u8 == 1_u8 {
                element.add(basis_element)
            } else {
                element
            }
        },
    ))
}

fn lagrange_coefficients(
    evaluation_points: &[BinaryFieldElement256],
    target: BinaryFieldElement256,
) -> Result<Vec<BinaryFieldElement256>, TallyPreparationError> {
    if evaluation_points.len() != EVALUATION_POINT_COUNT {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    evaluation_points
        .iter()
        .copied()
        .enumerate()
        .map(|(selected_position, selected_point)| {
            let mut numerator = BinaryFieldElement256::ONE;
            let mut denominator = BinaryFieldElement256::ONE;
            for (other_position, other_point) in evaluation_points.iter().copied().enumerate() {
                if other_position == selected_position {
                    continue;
                }
                numerator = numerator.multiply(target.add(other_point));
                denominator = denominator.multiply(selected_point.add(other_point));
            }
            numerator.divide(denominator)
        })
        .collect()
}

fn verify_lagrange_coefficients(
    evaluation_points: &[BinaryFieldElement256],
    coefficients: &[BinaryFieldElement256],
    target: BinaryFieldElement256,
) -> Result<(), TallyPreparationError> {
    if evaluation_points.len() != EVALUATION_POINT_COUNT
        || coefficients.len() != EVALUATION_POINT_COUNT
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let mut expected_target_power = BinaryFieldElement256::ONE;
    for exponent in 0..EVALUATION_POINT_COUNT {
        let interpolated_target_power = evaluation_points
            .iter()
            .copied()
            .zip(coefficients.iter().copied())
            .fold(
                BinaryFieldElement256::ZERO,
                |interpolated, (evaluation_point, coefficient)| {
                    interpolated.add(coefficient.multiply(field_power(evaluation_point, exponent)))
                },
            );
        if interpolated_target_power != expected_target_power {
            return Err(TallyPreparationError::GeometryMismatch);
        }
        expected_target_power = expected_target_power.multiply(target);
    }
    Ok(())
}

fn field_power(base: BinaryFieldElement256, exponent: usize) -> BinaryFieldElement256 {
    let mut power = BinaryFieldElement256::ONE;
    for _multiplication_position in 0..exponent {
        power = power.multiply(base);
    }
    power
}

fn evaluation_masks(
    evaluation_point: BinaryFieldElement256,
    subfield_power_basis: &[BinaryFieldElement256],
    canonical_to_tower_rows: &[BinaryLinearMask256],
) -> Result<[BinaryLinearMask256; SUBFIELD_BIT_LENGTH], TallyPreparationError> {
    if subfield_power_basis.len() != SUBFIELD_BIT_LENGTH
        || canonical_to_tower_rows.len() != CANONICAL_FIELD_BIT_LENGTH
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let mut masks = [BinaryLinearMask256::ZERO; SUBFIELD_BIT_LENGTH];
    let mut evaluation_point_power = BinaryFieldElement256::ONE;
    for tower_coefficient_position in 0..TOWER_EXTENSION_DEGREE {
        for (subfield_coefficient_position, subfield_basis_element) in
            subfield_power_basis.iter().copied().enumerate()
        {
            let evaluated_basis_element = subfield_basis_element.multiply(evaluation_point_power);
            let coordinates = tower_coordinates(evaluated_basis_element, canonical_to_tower_rows);
            if coordinates[SUBFIELD_BIT_LENGTH..]
                .iter()
                .any(|coordinate| *coordinate)
            {
                return Err(TallyPreparationError::GeometryMismatch);
            }
            let input_coordinate_position = tower_coefficient_position
                .checked_mul(SUBFIELD_BIT_LENGTH)
                .and_then(|position| position.checked_add(subfield_coefficient_position))
                .ok_or(TallyPreparationError::ArithmeticOverflow)?;
            for output_coordinate_position in 0..SUBFIELD_BIT_LENGTH {
                if coordinates[output_coordinate_position] {
                    masks[output_coordinate_position] = masks[output_coordinate_position]
                        .exclusive_or(canonical_to_tower_rows[input_coordinate_position]);
                }
            }
        }
        evaluation_point_power = evaluation_point_power.multiply(evaluation_point);
    }
    Ok(masks)
}

fn tower_coordinates(
    element: BinaryFieldElement256,
    canonical_to_tower_rows: &[BinaryLinearMask256],
) -> Vec<bool> {
    canonical_to_tower_rows
        .iter()
        .map(|coordinate_mask| coordinate_mask.parity(element))
        .collect()
}

fn subfield_karatsuba_terms() -> Vec<SubfieldBilinearTerm> {
    let coefficient_masks = (0..SUBFIELD_BIT_LENGTH)
        .map(|coefficient_position| 1_u8 << coefficient_position)
        .collect::<Vec<_>>();
    recursive_karatsuba_terms(&coefficient_masks, &coefficient_masks)
}

fn recursive_karatsuba_terms(
    left_coefficients: &[u8],
    right_coefficients: &[u8],
) -> Vec<SubfieldBilinearTerm> {
    assert_eq!(left_coefficients.len(), right_coefficients.len());
    assert!(!left_coefficients.is_empty());
    assert!(left_coefficients.len().is_power_of_two());
    if left_coefficients.len() == 1 {
        return vec![SubfieldBilinearTerm {
            left_mask: left_coefficients[0],
            right_mask: right_coefficients[0],
            raw_output_coefficients: 1_u16,
        }];
    }

    let half_length = left_coefficients.len() / 2;
    let left_low = &left_coefficients[..half_length];
    let left_high = &left_coefficients[half_length..];
    let right_low = &right_coefficients[..half_length];
    let right_high = &right_coefficients[half_length..];
    let left_sum = left_low
        .iter()
        .copied()
        .zip(left_high.iter().copied())
        .map(|(low, high)| low ^ high)
        .collect::<Vec<_>>();
    let right_sum = right_low
        .iter()
        .copied()
        .zip(right_high.iter().copied())
        .map(|(low, high)| low ^ high)
        .collect::<Vec<_>>();

    let mut terms = recursive_karatsuba_terms(left_low, right_low)
        .into_iter()
        .map(|mut term| {
            term.raw_output_coefficients ^= term.raw_output_coefficients << half_length;
            term
        })
        .collect::<Vec<_>>();
    terms.extend(
        recursive_karatsuba_terms(left_high, right_high)
            .into_iter()
            .map(|mut term| {
                term.raw_output_coefficients = (term.raw_output_coefficients << (half_length * 2))
                    ^ (term.raw_output_coefficients << half_length);
                term
            }),
    );
    terms.extend(
        recursive_karatsuba_terms(&left_sum, &right_sum)
            .into_iter()
            .map(|mut term| {
                term.raw_output_coefficients <<= half_length;
                term
            }),
    );
    terms
}

fn reduce_subfield_raw_output(
    raw_output_coefficients: u16,
    subfield_power_basis: &[BinaryFieldElement256],
    canonical_to_tower_rows: &[BinaryLinearMask256],
) -> Result<BinaryFieldElement256, TallyPreparationError> {
    let subfield_generator = *subfield_power_basis
        .get(1)
        .ok_or(TallyPreparationError::GeometryMismatch)?;
    let mut raw_power = BinaryFieldElement256::ONE;
    let mut output = BinaryFieldElement256::ZERO;
    for raw_coefficient_position in 0..(SUBFIELD_BIT_LENGTH * 2 - 1) {
        if (raw_output_coefficients >> raw_coefficient_position) & 1_u16 == 1_u16 {
            output = output.add(raw_power);
        }
        raw_power = raw_power.multiply(subfield_generator);
    }
    let coordinates = tower_coordinates(output, canonical_to_tower_rows);
    if coordinates[SUBFIELD_BIT_LENGTH..]
        .iter()
        .any(|coordinate| *coordinate)
    {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    let coordinate_byte = coordinates[..SUBFIELD_BIT_LENGTH]
        .iter()
        .copied()
        .enumerate()
        .fold(0_u8, |byte, (bit_position, bit)| {
            byte | (u8::from(bit) << bit_position)
        });
    let reconstructed_output = embed_subfield_coordinates(coordinate_byte, subfield_power_basis)?;
    if reconstructed_output != output {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    Ok(output)
}

fn combine_evaluation_masks(
    evaluation_masks: &[BinaryLinearMask256; SUBFIELD_BIT_LENGTH],
    selected_coordinates: u8,
) -> BinaryLinearMask256 {
    evaluation_masks.iter().copied().enumerate().fold(
        BinaryLinearMask256::ZERO,
        |combined_mask, (coordinate_position, coordinate_mask)| {
            if (selected_coordinates >> coordinate_position) & 1_u8 == 1_u8 {
                combined_mask.exclusive_or(coordinate_mask)
            } else {
                combined_mask
            }
        },
    )
}

fn distinct_input_masks(terms: &[CanonicalFieldBilinearTerm]) -> Vec<BinaryLinearMask256> {
    let mut masks = terms
        .iter()
        .flat_map(|term| [term.left_mask, term.right_mask])
        .collect::<Vec<_>>();
    masks.sort_unstable();
    masks.dedup();
    masks
}

fn binary_target(
    mask: BinaryLinearMask256,
    bit_length: usize,
) -> Result<Vec<bool>, TallyPreparationError> {
    if bit_length > CANONICAL_FIELD_BIT_LENGTH {
        return Err(TallyPreparationError::GeometryMismatch);
    }
    (0..bit_length)
        .map(|bit_position| mask.bit(bit_position))
        .collect()
}

fn output_targets(
    terms: &[CanonicalFieldBilinearTerm],
) -> Result<Vec<Vec<bool>>, TallyPreparationError> {
    let mut targets = vec![vec![false; terms.len()]; CANONICAL_FIELD_BIT_LENGTH];
    for (term_position, term) in terms.iter().enumerate() {
        let output_mask = BinaryLinearMask256::from_field_element(term.output);
        for (output_bit_position, target) in targets.iter_mut().enumerate() {
            target[term_position] = output_mask.bit(output_bit_position)?;
        }
    }
    Ok(targets)
}

fn canonical_bits(element: BinaryFieldElement256) -> Vec<bool> {
    let canonical_bytes = element.canonical_bytes();
    (0..CANONICAL_FIELD_BIT_LENGTH)
        .map(|bit_position| {
            (canonical_bytes[bit_position / u8::BITS as usize]
                >> (bit_position % u8::BITS as usize))
                & 1_u8
                == 1_u8
        })
        .collect()
}

fn exact_straight_line_exclusive_or_count(
    terms: &[CanonicalFieldBilinearTerm],
    distinct_input_masks: &[BinaryLinearMask256],
) -> Result<u64, TallyPreparationError> {
    let input_linear_form_exclusive_or_count =
        distinct_input_masks
            .iter()
            .try_fold(0_u64, |count, input_mask| {
                let input_weight = input_mask.hamming_weight();
                if input_weight == 0 {
                    return Err(TallyPreparationError::GeometryMismatch);
                }
                checked_add(count, input_weight - 1)
            })?;
    let both_operands_input_exclusive_or_count =
        checked_multiply(input_linear_form_exclusive_or_count, 2)?;
    let mut output_term_counts = [0_u64; CANONICAL_FIELD_BIT_LENGTH];
    for term in terms {
        let output_mask = BinaryLinearMask256::from_field_element(term.output);
        for (output_bit_position, output_term_count) in output_term_counts.iter_mut().enumerate() {
            if output_mask.bit(output_bit_position)? {
                *output_term_count = checked_add(*output_term_count, 1)?;
            }
        }
    }
    let output_exclusive_or_count = output_term_counts
        .iter()
        .try_fold(0_u64, |count, term_count| {
            checked_add(count, term_count.saturating_sub(1))
        })?;
    checked_add(
        both_operands_input_exclusive_or_count,
        output_exclusive_or_count,
    )
}

fn checked_add(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_add(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}

fn checked_multiply(left: u64, right: u64) -> Result<u64, TallyPreparationError> {
    left.checked_mul(right)
        .ok_or(TallyPreparationError::ArithmeticOverflow)
}
