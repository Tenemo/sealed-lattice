use super::{
    DATA_PRIMES, POLYNOMIAL_DEGREE, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentValue, invalid_commitment_input,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const SETUP_COMMITMENT_WORKER_RESPONSE_FORMAT_IDENTIFIER: u32 = u32::from_le_bytes(*b"SLCM");
const SETUP_COMMITMENT_WORKER_RESPONSE_VERSION: u32 = 1;
const SETUP_COMMITMENT_WORKER_RESPONSE_HEADER_BYTE_LENGTH: usize = 32;
const SETUP_COMMITMENT_WORKER_RESPONSE_LIMB_HEADER_BYTE_LENGTH: usize = 4;

pub(crate) fn setup_commitment_worker_response_bytes(
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<Vec<u8>> {
    validate_setup_commitment_worker_response_value(commitment)?;
    let residue_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .len()
        .checked_mul(SETUP_COMMITMENT_ROW_COUNT)
        .and_then(|count| count.checked_mul(POLYNOMIAL_DEGREE))
        .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
        .ok_or_else(|| response_length_error("setup commitment response length overflowed"))?;
    let limb_header_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .len()
        .checked_mul(SETUP_COMMITMENT_WORKER_RESPONSE_LIMB_HEADER_BYTE_LENGTH)
        .ok_or_else(|| response_length_error("setup commitment response length overflowed"))?;
    let response_byte_length = SETUP_COMMITMENT_WORKER_RESPONSE_HEADER_BYTE_LENGTH
        .checked_add(limb_header_byte_length)
        .and_then(|length| length.checked_add(residue_byte_length))
        .ok_or_else(|| response_length_error("setup commitment response length overflowed"))?;
    let mut response = Vec::new();
    response
        .try_reserve_exact(response_byte_length)
        .map_err(|_| {
            response_length_error("setup commitment response allocation exceeded the fixed profile")
        })?;
    response.extend_from_slice(&SETUP_COMMITMENT_WORKER_RESPONSE_FORMAT_IDENTIFIER.to_le_bytes());
    response.extend_from_slice(&SETUP_COMMITMENT_WORKER_RESPONSE_VERSION.to_le_bytes());
    response.extend_from_slice(
        &u32::try_from(commitment.source_rns_limb_index)
            .map_err(|_| invalid_commitment_input("source RNS limb index does not fit u32"))?
            .to_le_bytes(),
    );
    response.extend_from_slice(&commitment.shamir_coefficient_index.to_le_bytes());
    response.extend_from_slice(
        &u32::try_from(commitment.ring_degree)
            .map_err(|_| invalid_commitment_input("setup commitment ring degree does not fit u32"))?
            .to_le_bytes(),
    );
    response.extend_from_slice(
        &u32::try_from(commitment.limbs.len())
            .map_err(|_| invalid_commitment_input("setup commitment limb count does not fit u32"))?
            .to_le_bytes(),
    );
    response.extend_from_slice(
        &u32::try_from(SETUP_COMMITMENT_ROW_COUNT)
            .map_err(|_| invalid_commitment_input("setup commitment row count does not fit u32"))?
            .to_le_bytes(),
    );
    for limb in &commitment.limbs {
        response.extend_from_slice(
            &u32::try_from(limb.commitment_modulus_index)
                .map_err(|_| {
                    invalid_commitment_input("setup commitment modulus index does not fit u32")
                })?
                .to_le_bytes(),
        );
        for row in &limb.rows {
            for residue in row {
                response.extend_from_slice(&residue.to_le_bytes());
            }
        }
    }
    if response.len() != response_byte_length {
        return Err(response_length_error(
            "setup commitment response did not match its fixed production length",
        ));
    }
    Ok(response)
}

fn validate_setup_commitment_worker_response_value(
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<()> {
    if commitment.source_rns_limb_index >= DATA_PRIMES.len() {
        return Err(invalid_commitment_input(
            "setup commitment source RNS limb index is outside the data basis",
        ));
    }
    if commitment.ring_degree != POLYNOMIAL_DEGREE {
        return Err(response_length_error(
            "setup commitment response requires the complete selected ring",
        ));
    }
    if commitment.limbs.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(response_length_error(
            "setup commitment response must contain every selected modulus limb",
        ));
    }
    for (limb, expected_modulus_index) in commitment
        .limbs
        .iter()
        .zip(SETUP_COMMITMENT_MODULUS_LIMB_INDICES)
    {
        let expected_modulus = DATA_PRIMES[expected_modulus_index];
        if limb.commitment_modulus_index != expected_modulus_index
            || limb.modulus != expected_modulus
        {
            return Err(invalid_commitment_input(
                "setup commitment response modulus limbs are not in selected order",
            ));
        }
        if limb.rows.len() != SETUP_COMMITMENT_ROW_COUNT
            || limb.rows.iter().any(|row| row.len() != POLYNOMIAL_DEGREE)
        {
            return Err(response_length_error(
                "setup commitment response rows must match the fixed selected shape",
            ));
        }
        if limb
            .rows
            .iter()
            .flatten()
            .any(|residue| *residue >= expected_modulus)
        {
            return Err(invalid_commitment_input(
                "setup commitment response residue is outside its selected modulus",
            ));
        }
    }
    Ok(())
}

fn response_length_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::MalformedLength, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::setup::commitment::SetupCommitmentLimb;

    fn selected_commitment() -> SetupCommitmentValue {
        SetupCommitmentValue {
            source_rns_limb_index: DATA_PRIMES.len() - 1,
            shamir_coefficient_index: 4,
            ring_degree: POLYNOMIAL_DEGREE,
            limbs: SETUP_COMMITMENT_MODULUS_LIMB_INDICES
                .iter()
                .copied()
                .map(|commitment_modulus_index| {
                    let modulus = DATA_PRIMES[commitment_modulus_index];
                    SetupCommitmentLimb {
                        commitment_modulus_index,
                        modulus,
                        rows: (0..SETUP_COMMITMENT_ROW_COUNT)
                            .map(|row_index| {
                                (0..POLYNOMIAL_DEGREE)
                                    .map(|coefficient_index| {
                                        (coefficient_index as u64 + row_index as u64) % modulus
                                    })
                                    .collect()
                            })
                            .collect(),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn worker_response_has_exact_production_shape_and_order() -> CanonicalResult<()> {
        let commitment = selected_commitment();
        let response = setup_commitment_worker_response_bytes(&commitment)?;
        let expected_byte_length = SETUP_COMMITMENT_WORKER_RESPONSE_HEADER_BYTE_LENGTH
            + SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
                * SETUP_COMMITMENT_WORKER_RESPONSE_LIMB_HEADER_BYTE_LENGTH
            + SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
                * SETUP_COMMITMENT_ROW_COUNT
                * POLYNOMIAL_DEGREE
                * std::mem::size_of::<u64>();
        assert_eq!(response.len(), expected_byte_length);
        assert_eq!(response.len(), 1_572_908);
        assert_eq!(
            u32::from_le_bytes(response[0..4].try_into().expect("format identifier")),
            SETUP_COMMITMENT_WORKER_RESPONSE_FORMAT_IDENTIFIER
        );
        assert_eq!(
            u32::from_le_bytes(response[4..8].try_into().expect("format version")),
            SETUP_COMMITMENT_WORKER_RESPONSE_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(response[8..12].try_into().expect("source limb")) as usize,
            commitment.source_rns_limb_index
        );
        assert_eq!(
            u64::from_le_bytes(response[12..20].try_into().expect("coefficient index")),
            commitment.shamir_coefficient_index
        );
        assert_eq!(
            u32::from_le_bytes(response[20..24].try_into().expect("ring degree")) as usize,
            POLYNOMIAL_DEGREE
        );
        assert_eq!(
            u32::from_le_bytes(response[24..28].try_into().expect("limb count")) as usize,
            SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()
        );
        assert_eq!(
            u32::from_le_bytes(response[28..32].try_into().expect("row count")) as usize,
            SETUP_COMMITMENT_ROW_COUNT
        );
        let limb_byte_length = SETUP_COMMITMENT_WORKER_RESPONSE_LIMB_HEADER_BYTE_LENGTH
            + SETUP_COMMITMENT_ROW_COUNT * POLYNOMIAL_DEGREE * std::mem::size_of::<u64>();
        for (limb_position, expected_modulus_index) in SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .copied()
            .enumerate()
        {
            let limb_offset = SETUP_COMMITMENT_WORKER_RESPONSE_HEADER_BYTE_LENGTH
                + limb_position * limb_byte_length;
            assert_eq!(
                u32::from_le_bytes(
                    response[limb_offset..limb_offset + 4]
                        .try_into()
                        .expect("modulus index")
                ) as usize,
                expected_modulus_index
            );
            let first_residue_offset = limb_offset + 4;
            assert_eq!(
                u64::from_le_bytes(
                    response[first_residue_offset..first_residue_offset + 8]
                        .try_into()
                        .expect("first residue")
                ),
                commitment.limbs[limb_position].rows[0][0]
            );
            let final_residue_offset = limb_offset + limb_byte_length - 8;
            assert_eq!(
                u64::from_le_bytes(
                    response[final_residue_offset..final_residue_offset + 8]
                        .try_into()
                        .expect("final residue")
                ),
                commitment.limbs[limb_position].rows[SETUP_COMMITMENT_ROW_COUNT - 1]
                    [POLYNOMIAL_DEGREE - 1]
            );
        }
        Ok(())
    }

    #[test]
    fn worker_response_rejects_malformed_typed_commitments() {
        let mut wrong_source = selected_commitment();
        wrong_source.source_rns_limb_index = DATA_PRIMES.len();
        assert!(setup_commitment_worker_response_bytes(&wrong_source).is_err());

        let mut wrong_degree = selected_commitment();
        wrong_degree.ring_degree /= 2;
        assert!(setup_commitment_worker_response_bytes(&wrong_degree).is_err());

        let mut missing_limb = selected_commitment();
        missing_limb.limbs.pop();
        assert!(setup_commitment_worker_response_bytes(&missing_limb).is_err());

        let mut wrong_modulus_index = selected_commitment();
        wrong_modulus_index.limbs[1].commitment_modulus_index = 7;
        assert!(setup_commitment_worker_response_bytes(&wrong_modulus_index).is_err());

        let mut missing_row = selected_commitment();
        missing_row.limbs[0].rows.pop();
        assert!(setup_commitment_worker_response_bytes(&missing_row).is_err());

        let mut short_row = selected_commitment();
        short_row.limbs[0].rows[0].pop();
        assert!(setup_commitment_worker_response_bytes(&short_row).is_err());

        let mut out_of_range_residue = selected_commitment();
        out_of_range_residue.limbs[2].rows[1][POLYNOMIAL_DEGREE - 1] =
            DATA_PRIMES[SETUP_COMMITMENT_MODULUS_LIMB_INDICES[2]];
        assert!(setup_commitment_worker_response_bytes(&out_of_range_residue).is_err());
    }
}
