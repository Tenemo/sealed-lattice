#[cfg(test)]
use super::commitment_parameters::*;
#[cfg(test)]
use super::computation::*;
#[cfg(test)]
use super::serialization::*;
#[cfg(test)]
use super::validation::*;
#[cfg(test)]
use super::*;

#[cfg(test)]
pub(super) fn verify_setup_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    let source_message_modulus = DATA_PRIMES
        .get(expected_commitment.source_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            invalid_commitment_input(
                "commitment source RNS limb is outside the selected Q_share prime list",
            )
        })?;
    verify_setup_commitment_opening_with_message_bound(
        public_matrix_seed_hash,
        expected_commitment,
        message_coefficients,
        randomness_by_commitment_limb,
        randomness_infinity_bound,
        Some(u128::from(source_message_modulus)),
    )
}

#[cfg(test)]
pub(in super::super) fn verify_setup_lifted_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    verify_setup_commitment_opening_with_message_bound(
        public_matrix_seed_hash,
        expected_commitment,
        message_coefficients,
        randomness_by_commitment_limb,
        randomness_infinity_bound,
        None,
    )
}

#[cfg(test)]
pub(super) fn verify_setup_signed_lifted_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[i128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    validate_signed_message_coefficients(message_coefficients, expected_commitment.ring_degree)?;
    validate_randomness_by_commitment_limb(
        randomness_by_commitment_limb,
        randomness_infinity_bound,
        expected_commitment.ring_degree,
    )?;
    let message_coefficient_bound =
        signed_message_coefficient_magnitude_bound(message_coefficients)?;
    let signed_message_coefficient_bound =
        i128::try_from(message_coefficient_bound).map_err(|_| {
            invalid_commitment_input(
                "signed commitment message coefficient magnitude does not fit i128",
            )
        })?;
    if !setup_signed_coefficient_fits_centered_commitment_modulus_product(
        signed_message_coefficient_bound,
    ) {
        return Err(invalid_commitment_input(
            "signed commitment message coefficient would wrap in the centered CRT commitment modulus",
        ));
    }

    let computed_commitment = compute_setup_signed_lifted_commitment_for_degree(
        public_matrix_seed_hash,
        expected_commitment.source_rns_limb_index,
        expected_commitment.shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        expected_commitment.ring_degree,
    )?;
    if &computed_commitment != expected_commitment {
        return Err(invalid_commitment_input(
            "signed commitment opening does not reproduce the published commitment",
        ));
    }

    Ok(SetupCommitmentOpeningVerification {
        commitment_root: setup_commitment_root(&computed_commitment)?,
        message_coefficient_bound,
    })
}

#[cfg(test)]
fn verify_setup_commitment_opening_with_message_bound(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    randomness_infinity_bound: i128,
    message_exclusive_bound: Option<u128>,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    validate_message_coefficients(
        message_coefficients,
        message_exclusive_bound,
        expected_commitment.ring_degree,
    )?;
    validate_randomness_by_commitment_limb(
        randomness_by_commitment_limb,
        randomness_infinity_bound,
        expected_commitment.ring_degree,
    )?;
    let message_coefficient_bound = message_coefficients.iter().copied().max().unwrap_or(0);
    if !setup_coefficient_fits_commitment_modulus_product(message_coefficient_bound) {
        return Err(invalid_commitment_input(
            "commitment message coefficient would wrap in the CRT commitment modulus",
        ));
    }

    let computed_commitment = compute_setup_commitment_for_degree(
        public_matrix_seed_hash,
        expected_commitment.source_rns_limb_index,
        expected_commitment.shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        expected_commitment.ring_degree,
    )?;
    if &computed_commitment != expected_commitment {
        return Err(invalid_commitment_input(
            "commitment opening does not reproduce the published commitment",
        ));
    }

    Ok(SetupCommitmentOpeningVerification {
        commitment_root: setup_commitment_root(&computed_commitment)?,
        message_coefficient_bound,
    })
}

#[cfg(test)]
pub(super) fn validate_same_commitment_domain(
    first_commitment: &SetupCommitmentValue,
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<()> {
    if first_commitment.source_rns_limb_index != commitment.source_rns_limb_index
        || first_commitment.ring_degree != commitment.ring_degree
        || first_commitment.limbs.len() != commitment.limbs.len()
    {
        return Err(invalid_commitment_input(
            "commitment linear combination terms must share the same source and ring domain",
        ));
    }
    for (first_limb, limb) in first_commitment.limbs.iter().zip(commitment.limbs.iter()) {
        if first_limb.commitment_modulus_index != limb.commitment_modulus_index
            || first_limb.modulus != limb.modulus
            || first_limb.rows.len() != limb.rows.len()
        {
            return Err(invalid_commitment_input(
                "commitment linear combination terms must share the same commitment limb shape",
            ));
        }
    }

    Ok(())
}
