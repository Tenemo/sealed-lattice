use core::mem::size_of;

use super::{
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
    SETUP_COMMITMENT_ROW_COUNT, StructuralMatrixPolynomial, add_mod_fast, forward_negacyclic_ntt,
    invalid_commitment_input, inverse_negacyclic_ntt, mul_mod_fast, setup_commitment_matrix_ntt,
    structural_matrix_polynomial_kind,
};
use crate::{
    bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple},
};

const LATTICE_ANCHOR_COMMITMENT_SCHEMA_IDENTIFIER: u16 = 0x2124;
const LATTICE_COMMITMENT_ROW_SCHEMA_IDENTIFIER: u16 = 0x2125;
const LATTICE_COMMITMENT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LatticeAnchorCommitment {
    pub(crate) commitment_data_prime_index: usize,
    pub(crate) ring_degree: usize,
    pub(crate) rows: Vec<Vec<u64>>,
}

pub(crate) fn lattice_anchor_commitment_canonical_bytes(
    commitment: &LatticeAnchorCommitment,
) -> CanonicalResult<Vec<u8>> {
    let modulus = selected_commitment_prime(commitment.commitment_data_prime_index)?;
    if commitment.ring_degree != POLYNOMIAL_DEGREE
        || commitment.rows.len() != SETUP_COMMITMENT_ROW_COUNT
        || commitment
            .rows
            .iter()
            .any(|row| row.len() != POLYNOMIAL_DEGREE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "canonical lattice anchor commitment must contain the complete selected ring",
        ));
    }
    if commitment
        .rows
        .iter()
        .flatten()
        .any(|residue| *residue >= modulus)
    {
        return Err(invalid_commitment_input(
            "lattice anchor row coefficient is outside its commitment prime",
        ));
    }

    let limits = lattice_anchor_decode_limits();
    let field_element_byte_length = field_element_byte_length(modulus);
    let row_items = commitment
        .rows
        .iter()
        .map(|row| {
            let field_list_byte_length = 6usize
                .checked_add(
                    row.len()
                        .checked_mul(field_element_byte_length)
                        .ok_or_else(|| {
                            invalid_commitment_input("lattice commitment row byte length overflows")
                        })?,
                )
                .ok_or_else(|| {
                    invalid_commitment_input("lattice commitment row byte length overflows")
                })?;
            let mut field_list_bytes = Vec::with_capacity(field_list_byte_length);
            field_list_bytes.extend_from_slice(
                &CanonicalItemType::FieldElement
                    .canonical_code()
                    .to_le_bytes(),
            );
            field_list_bytes.extend_from_slice(
                &u32::try_from(row.len())
                    .map_err(|_| {
                        invalid_commitment_input(
                            "lattice commitment row coefficient count does not fit u32",
                        )
                    })?
                    .to_le_bytes(),
            );
            for residue in row {
                field_list_bytes
                    .extend_from_slice(&residue.to_le_bytes()[..field_element_byte_length]);
            }
            let row_tuple = CanonicalTuple::new(
                LATTICE_COMMITMENT_ROW_SCHEMA_IDENTIFIER,
                LATTICE_COMMITMENT_SCHEMA_VERSION,
                vec![
                    CanonicalItem::from_canonical_bytes(
                        CanonicalItemType::HomogeneousList,
                        field_list_bytes,
                        &limits,
                    )
                    .map_err(canonical_codec_error)?,
                ],
            );
            CanonicalItem::nested_tuple_with_limits(&row_tuple, &limits)
                .map_err(canonical_codec_error)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let commitment_data_prime_index = u16::try_from(commitment.commitment_data_prime_index)
        .map_err(|_| invalid_commitment_input("lattice anchor prime index does not fit u16"))?;
    CanonicalTuple::new(
        LATTICE_ANCHOR_COMMITMENT_SCHEMA_IDENTIFIER,
        LATTICE_COMMITMENT_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(commitment_data_prime_index),
            CanonicalItem::homogeneous_list_with_limits(
                CanonicalItemType::NestedTuple,
                &row_items,
                &limits,
            )
            .map_err(canonical_codec_error)?,
        ],
    )
    .encode_with_limits(&limits)
    .map_err(canonical_codec_error)
}

/// Exact selected-shape encoding length without constructing the complete
/// commitment rows. This follows the same tuple and homogeneous-list layout
/// used by `lattice_anchor_commitment_canonical_bytes`.
pub(crate) fn selected_lattice_anchor_commitment_canonical_byte_length(
    commitment_data_prime_index: usize,
) -> CanonicalResult<usize> {
    let modulus = selected_commitment_prime(commitment_data_prime_index)?;
    let field_element_byte_length = field_element_byte_length(modulus);
    let field_list_byte_length = 6_usize
        .checked_add(
            POLYNOMIAL_DEGREE
                .checked_mul(field_element_byte_length)
                .ok_or_else(|| {
                    invalid_commitment_input("lattice commitment row byte length overflows")
                })?,
        )
        .ok_or_else(|| invalid_commitment_input("lattice commitment row byte length overflows"))?;
    let row_tuple_byte_length = 8_usize
        .checked_add(6)
        .and_then(|length| length.checked_add(field_list_byte_length))
        .ok_or_else(|| {
            invalid_commitment_input("lattice commitment row tuple byte length overflows")
        })?;
    let row_list_byte_length = SETUP_COMMITMENT_ROW_COUNT
        .checked_mul(row_tuple_byte_length)
        .and_then(|length| length.checked_add(6))
        .ok_or_else(|| {
            invalid_commitment_input("lattice commitment row list byte length overflows")
        })?;
    8_usize
        .checked_add(6 + size_of::<u16>())
        .and_then(|length| length.checked_add(6))
        .and_then(|length| length.checked_add(row_list_byte_length))
        .ok_or_else(|| invalid_commitment_input("lattice commitment byte length overflows"))
}

pub(crate) fn parse_lattice_anchor_commitment_canonical_bytes(
    canonical_bytes: &[u8],
) -> CanonicalResult<LatticeAnchorCommitment> {
    let limits = lattice_anchor_decode_limits();
    let tuple = CanonicalTuple::decode(canonical_bytes, &limits).map_err(canonical_codec_error)?;
    if tuple.schema_identifier != LATTICE_ANCHOR_COMMITMENT_SCHEMA_IDENTIFIER
        || tuple.schema_version != LATTICE_COMMITMENT_SCHEMA_VERSION
        || tuple.items.len() != 2
    {
        return Err(invalid_commitment_input(
            "lattice anchor commitment schema, version, or item count is invalid",
        ));
    }
    let commitment_data_prime_index = read_canonical_u16(&tuple.items[0])? as usize;
    let modulus = selected_commitment_prime(commitment_data_prime_index)?;
    let row_tuples = decode_nested_tuple_list(&tuple.items[1], &limits)?;
    if row_tuples.len() != SETUP_COMMITMENT_ROW_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice anchor commitment must contain the selected row count",
        ));
    }
    let rows = row_tuples
        .iter()
        .map(|row_tuple| decode_lattice_commitment_row(row_tuple, modulus))
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(LatticeAnchorCommitment {
        commitment_data_prime_index,
        ring_degree: POLYNOMIAL_DEGREE,
        rows,
    })
}

pub(crate) fn compute_lattice_anchor_commitment<OpeningPolynomial>(
    public_matrix_seed_hash: &str,
    commitment_data_prime_index: usize,
    secret_contribution_coefficients: &[i8],
    opening_polynomials: &[OpeningPolynomial],
) -> CanonicalResult<LatticeAnchorCommitment>
where
    OpeningPolynomial: AsRef<[i8]>,
{
    compute_lattice_anchor_commitment_for_degree(
        public_matrix_seed_hash,
        commitment_data_prime_index,
        secret_contribution_coefficients,
        opening_polynomials,
        POLYNOMIAL_DEGREE,
    )
}

fn compute_lattice_anchor_commitment_for_degree<OpeningPolynomial>(
    public_matrix_seed_hash: &str,
    commitment_data_prime_index: usize,
    secret_contribution_coefficients: &[i8],
    opening_polynomials: &[OpeningPolynomial],
    ring_degree: usize,
) -> CanonicalResult<LatticeAnchorCommitment>
where
    OpeningPolynomial: AsRef<[i8]>,
{
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let modulus = selected_commitment_prime(commitment_data_prime_index)?;
    validate_anchor_ring_degree(ring_degree)?;
    validate_centered_ternary_vector(
        secret_contribution_coefficients,
        ring_degree,
        "secret contribution",
    )?;
    if opening_polynomials.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice anchor opening must contain exactly three prime-local polynomials",
        ));
    }
    for opening_polynomial in opening_polynomials {
        validate_centered_ternary_vector(
            opening_polynomial.as_ref(),
            ring_degree,
            "opening polynomial",
        )?;
    }

    let message_residues = secret_contribution_coefficients
        .iter()
        .map(|coefficient| centered_i8_to_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let opening_residues = opening_polynomials
        .iter()
        .map(|polynomial| {
            polynomial
                .as_ref()
                .iter()
                .map(|coefficient| centered_i8_to_residue(*coefficient, modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut opening_ntts: Vec<Option<Vec<u64>>> = vec![None; SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let mut rows = Vec::with_capacity(SETUP_COMMITMENT_ROW_COUNT);
    for matrix_row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
        let mut row_ntt = vec![0_u64; ring_degree];
        let mut has_sampled_matrix_product = false;
        for randomness_column_index in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
            if structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index)
                .is_some()
            {
                continue;
            }
            if opening_ntts[randomness_column_index].is_none() {
                opening_ntts[randomness_column_index] = Some(forward_negacyclic_ntt(
                    &opening_residues[randomness_column_index],
                    modulus,
                )?);
            }
            let matrix_ntt = setup_commitment_matrix_ntt(
                public_matrix_seed_hash,
                commitment_data_prime_index,
                matrix_row_index,
                randomness_column_index,
                ring_degree,
                modulus,
            )?;
            let opening_ntt = opening_ntts[randomness_column_index]
                .as_ref()
                .expect("an opening NTT is populated before use");
            for ((accumulated_value, matrix_value), opening_value) in row_ntt
                .iter_mut()
                .zip(matrix_ntt.iter())
                .zip(opening_ntt.iter())
            {
                *accumulated_value = add_mod_fast(
                    *accumulated_value,
                    mul_mod_fast(*matrix_value, *opening_value, modulus),
                    modulus,
                );
            }
            has_sampled_matrix_product = true;
        }
        let mut row = if has_sampled_matrix_product {
            inverse_negacyclic_ntt(&row_ntt, modulus)?
        } else {
            vec![0_u64; ring_degree]
        };
        for (randomness_column_index, opening_polynomial) in opening_residues.iter().enumerate() {
            match structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index) {
                Some(StructuralMatrixPolynomial::One) => {
                    for (accumulated_value, opening_value) in
                        row.iter_mut().zip(opening_polynomial.iter())
                    {
                        *accumulated_value =
                            add_mod_fast(*accumulated_value, *opening_value, modulus);
                    }
                }
                Some(StructuralMatrixPolynomial::Zero) | None => {}
            }
        }
        if matrix_row_index + 1 == SETUP_COMMITMENT_ROW_COUNT {
            for (accumulated_value, message_value) in row.iter_mut().zip(message_residues.iter()) {
                *accumulated_value = add_mod_fast(*accumulated_value, *message_value, modulus);
            }
        }
        rows.push(row);
    }

    Ok(LatticeAnchorCommitment {
        commitment_data_prime_index,
        ring_degree,
        rows,
    })
}

fn selected_commitment_prime(commitment_data_prime_index: usize) -> CanonicalResult<u64> {
    if !SETUP_COMMITMENT_MODULUS_LIMB_INDICES.contains(&commitment_data_prime_index) {
        return Err(invalid_commitment_input(
            "lattice anchor prime index is outside the selected commitment primes",
        ));
    }
    DATA_PRIMES
        .get(commitment_data_prime_index)
        .copied()
        .ok_or_else(|| {
            invalid_commitment_input("lattice anchor prime index is outside data primes")
        })
}

fn validate_anchor_ring_degree(ring_degree: usize) -> CanonicalResult<()> {
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || !ring_degree.is_power_of_two()
        || !POLYNOMIAL_DEGREE.is_multiple_of(ring_degree)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice anchor ring degree must be a power-of-two divisor of the selected ring degree",
        ));
    }
    Ok(())
}

fn validate_centered_ternary_vector(
    coefficients: &[i8],
    ring_degree: usize,
    description: &str,
) -> CanonicalResult<()> {
    if coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{description} coefficient count must match the ring degree"),
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_commitment_input(format!(
            "{description} coefficients must be centered ternary"
        )));
    }
    Ok(())
}

fn centered_i8_to_residue(coefficient: i8, modulus: u64) -> u64 {
    match coefficient {
        -1 => modulus - 1,
        0 => 0,
        1 => 1,
        _ => unreachable!("centered ternary support was validated"),
    }
}

fn lattice_anchor_decode_limits() -> CanonicalDecodeLimits {
    CanonicalDecodeLimits {
        maximum_item_count: POLYNOMIAL_DEGREE,
        ..CanonicalDecodeLimits::default()
    }
}

fn field_element_byte_length(modulus: u64) -> usize {
    let bit_length = u64::BITS as usize - (modulus - 1).leading_zeros() as usize;
    bit_length.div_ceil(8)
}

fn canonical_codec_error(error: crate::foundation::CanonicalCodecError) -> CanonicalError {
    invalid_commitment_input(format!(
        "lattice anchor canonical encoding is invalid: {error}"
    ))
}

fn read_canonical_u16(item: &CanonicalItem) -> CanonicalResult<u16> {
    if item.item_type() != CanonicalItemType::Unsigned16 || item.canonical_bytes().len() != 2 {
        return Err(invalid_commitment_input(
            "lattice anchor prime index must be a canonical u16",
        ));
    }
    Ok(u16::from_le_bytes([
        item.canonical_bytes()[0],
        item.canonical_bytes()[1],
    ]))
}

fn decode_nested_tuple_list(
    item: &CanonicalItem,
    limits: &CanonicalDecodeLimits,
) -> CanonicalResult<Vec<CanonicalTuple>> {
    let bytes = item.canonical_bytes();
    if item.item_type() != CanonicalItemType::HomogeneousList || bytes.len() < 6 {
        return Err(invalid_commitment_input(
            "lattice anchor rows must be a canonical homogeneous list",
        ));
    }
    let element_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    if element_type != CanonicalItemType::NestedTuple.canonical_code() {
        return Err(invalid_commitment_input(
            "lattice anchor rows must contain nested row tuples",
        ));
    }
    let row_count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if row_count != SETUP_COMMITMENT_ROW_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice anchor commitment must contain the selected row count",
        ));
    }
    let mut offset = 6usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let tuple_byte_length = canonical_tuple_byte_length(&bytes[offset..])?;
        let end = offset.checked_add(tuple_byte_length).ok_or_else(|| {
            invalid_commitment_input("lattice anchor row byte boundary overflows")
        })?;
        if end > bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "lattice anchor row tuple is truncated",
            ));
        }
        rows.push(
            CanonicalTuple::decode(&bytes[offset..end], limits).map_err(canonical_codec_error)?,
        );
        offset = end;
    }
    if offset != bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TrailingBytes,
            "lattice anchor row list contains trailing bytes",
        ));
    }
    Ok(rows)
}

fn canonical_tuple_byte_length(bytes: &[u8]) -> CanonicalResult<usize> {
    if bytes.len() < 8 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice anchor nested row header is truncated",
        ));
    }
    let item_count = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let mut offset = 8usize;
    for _ in 0..item_count {
        let header_end = offset.checked_add(6).ok_or_else(|| {
            invalid_commitment_input("lattice anchor nested row header overflows")
        })?;
        if header_end > bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "lattice anchor nested row item header is truncated",
            ));
        }
        let item_byte_length = u32::from_le_bytes([
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        ]) as usize;
        offset = header_end.checked_add(item_byte_length).ok_or_else(|| {
            invalid_commitment_input("lattice anchor nested row item boundary overflows")
        })?;
        if offset > bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "lattice anchor nested row item is truncated",
            ));
        }
    }
    Ok(offset)
}

fn decode_lattice_commitment_row(
    tuple: &CanonicalTuple,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if tuple.schema_identifier != LATTICE_COMMITMENT_ROW_SCHEMA_IDENTIFIER
        || tuple.schema_version != LATTICE_COMMITMENT_SCHEMA_VERSION
        || tuple.items.len() != 1
    {
        return Err(invalid_commitment_input(
            "lattice commitment row schema, version, or item count is invalid",
        ));
    }
    let list = &tuple.items[0];
    let bytes = list.canonical_bytes();
    if list.item_type() != CanonicalItemType::HomogeneousList || bytes.len() < 6 {
        return Err(invalid_commitment_input(
            "lattice commitment row must contain one field-element list",
        ));
    }
    let element_type = u16::from_le_bytes([bytes[0], bytes[1]]);
    if element_type != CanonicalItemType::FieldElement.canonical_code() {
        return Err(invalid_commitment_input(
            "lattice commitment row list must contain field elements",
        ));
    }
    let coefficient_count = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if coefficient_count != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice commitment row must contain the complete selected ring",
        ));
    }
    let field_element_byte_length = field_element_byte_length(modulus);
    let expected_payload_byte_length = coefficient_count
        .checked_mul(field_element_byte_length)
        .ok_or_else(|| invalid_commitment_input("lattice commitment row length overflows"))?;
    if bytes.len() != 6 + expected_payload_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "lattice commitment row field-element width is not canonical",
        ));
    }
    bytes[6..]
        .chunks_exact(field_element_byte_length)
        .map(|field_bytes| {
            let mut residue_bytes = [0_u8; 8];
            residue_bytes[..field_element_byte_length].copy_from_slice(field_bytes);
            let residue = u64::from_le_bytes(residue_bytes);
            if residue >= modulus {
                return Err(invalid_commitment_input(
                    "lattice anchor row coefficient is outside its commitment prime",
                ));
            }
            Ok(residue)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RING_DEGREE: usize = 8;

    #[test]
    fn exact_prime_local_anchor_uses_the_selected_shape() -> CanonicalResult<()> {
        let secret = vec![-1, 0, 1, -1, 1, 0, -1, 1];
        let opening = opening_polynomials();
        let commitment = compute_lattice_anchor_commitment_for_degree(
            &"ab".repeat(64),
            1,
            &secret,
            &opening,
            TEST_RING_DEGREE,
        )?;
        assert_eq!(commitment.rows.len(), 2);
        assert_eq!(commitment.rows[0].len(), TEST_RING_DEGREE);
        Ok(())
    }

    #[test]
    fn canonical_anchor_round_trips_and_body_tampering_changes_its_bytes() -> CanonicalResult<()> {
        let modulus = DATA_PRIMES[1];
        let commitment = LatticeAnchorCommitment {
            commitment_data_prime_index: 1,
            ring_degree: POLYNOMIAL_DEGREE,
            rows: (0..SETUP_COMMITMENT_ROW_COUNT)
                .map(|row_index| {
                    (0..POLYNOMIAL_DEGREE)
                        .map(|coefficient_index| {
                            ((row_index * POLYNOMIAL_DEGREE) + coefficient_index) as u64 % modulus
                        })
                        .collect()
                })
                .collect(),
        };
        let canonical_bytes = lattice_anchor_commitment_canonical_bytes(&commitment)?;
        assert_eq!(
            canonical_bytes.len(),
            selected_lattice_anchor_commitment_canonical_byte_length(1)?
        );
        assert_eq!(
            parse_lattice_anchor_commitment_canonical_bytes(&canonical_bytes)?,
            commitment
        );

        let mut tampered = commitment;
        tampered.rows[1][3] = (tampered.rows[1][3] + 1) % modulus;
        assert_ne!(
            lattice_anchor_commitment_canonical_bytes(&tampered)?,
            canonical_bytes
        );
        Ok(())
    }

    #[test]
    fn anchor_rejects_wrong_prime_shape_and_support() {
        let secret = vec![0_i8; TEST_RING_DEGREE];
        let opening = opening_polynomials();
        assert!(
            compute_lattice_anchor_commitment_for_degree(
                &"cd".repeat(64),
                3,
                &secret,
                &opening,
                TEST_RING_DEGREE,
            )
            .is_err()
        );

        let mut wrong_width = opening.clone();
        wrong_width.pop();
        assert!(
            compute_lattice_anchor_commitment_for_degree(
                &"cd".repeat(64),
                0,
                &secret,
                &wrong_width,
                TEST_RING_DEGREE,
            )
            .is_err()
        );

        let mut out_of_support = opening;
        out_of_support[2][5] = 2;
        assert!(
            compute_lattice_anchor_commitment_for_degree(
                &"cd".repeat(64),
                0,
                &secret,
                &out_of_support,
                TEST_RING_DEGREE,
            )
            .is_err()
        );
    }

    #[test]
    fn every_prime_uses_an_independent_opening_and_prime_local_rows() -> CanonicalResult<()> {
        let secret = vec![1_i8; TEST_RING_DEGREE];
        let opening = opening_polynomials();
        let anchors = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .map(|prime_index| {
                compute_lattice_anchor_commitment_for_degree(
                    &"ef".repeat(64),
                    *prime_index,
                    &secret,
                    &opening,
                    TEST_RING_DEGREE,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        assert_eq!(anchors.len(), 3);
        for (anchor, prime_index) in anchors.iter().zip(SETUP_COMMITMENT_MODULUS_LIMB_INDICES) {
            assert_eq!(anchor.commitment_data_prime_index, prime_index);
            assert!(
                anchor
                    .rows
                    .iter()
                    .flatten()
                    .all(|residue| *residue < DATA_PRIMES[prime_index])
            );
        }
        assert_ne!(anchors[0].rows, anchors[1].rows);
        assert_ne!(anchors[1].rows, anchors[2].rows);
        Ok(())
    }

    fn opening_polynomials() -> Vec<Vec<i8>> {
        (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .map(|column_index| {
                (0..TEST_RING_DEGREE)
                    .map(
                        |coefficient_index| match (column_index + coefficient_index) % 3 {
                            0 => -1,
                            1 => 0,
                            _ => 1,
                        },
                    )
                    .collect()
            })
            .collect()
    }
}
