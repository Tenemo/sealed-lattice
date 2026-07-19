#[cfg(test)]
use crate::bgv::parameters::DATA_PRIMES;
#[cfg(test)]
use num_bigint::BigUint;

pub(crate) const SETUP_COMMITMENT_MODULE_RANK: usize = 1;
#[cfg(test)]
pub(in super::super) const SETUP_COMMITMENT_HIDING_SECRET_DISTRIBUTION_PURPOSE: u16 = 11;
#[cfg(test)]
pub(in super::super) const SETUP_COMMITMENT_HIDING_ERROR_DISTRIBUTION_PURPOSE: u16 = 12;
pub(crate) const SETUP_COMMITMENT_HIDING_SECRET_WIDTH: usize = SETUP_COMMITMENT_MODULE_RANK + 1;
pub(crate) const SETUP_COMMITMENT_HIDING_ERROR_WIDTH: usize = SETUP_COMMITMENT_MODULE_RANK;
pub(crate) const SETUP_COMMITMENT_RANDOMNESS_WIDTH: usize =
    SETUP_COMMITMENT_HIDING_SECRET_WIDTH + SETUP_COMMITMENT_HIDING_ERROR_WIDTH;
pub(in super::super) const SETUP_COMMITMENT_ROW_COUNT: usize = SETUP_COMMITMENT_MODULE_RANK + 1;
#[cfg(test)]
pub(in super::super) const SETUP_COMMITMENT_HIDING_SECRET_COEFFICIENT_BOUND: i128 = 1;
#[cfg(test)]
pub(in super::super) const SETUP_COMMITMENT_HIDING_ERROR_COEFFICIENT_BOUND: i128 = 1;
// Three data-prime limbs set the CRT message-space ceiling; lifted linear
// combinations must stay below their product or binding breaks, which is why the
// carry relation is required above one q_l.
pub(crate) const SETUP_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];

#[cfg(test)]
pub(in super::super) const fn setup_commitment_randomness_coefficient_bound(
    randomness_column_index: usize,
) -> Option<i128> {
    if randomness_column_index < SETUP_COMMITMENT_HIDING_SECRET_WIDTH {
        Some(SETUP_COMMITMENT_HIDING_SECRET_COEFFICIENT_BOUND)
    } else if randomness_column_index < SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        Some(SETUP_COMMITMENT_HIDING_ERROR_COEFFICIENT_BOUND)
    } else {
        None
    }
}

#[cfg(test)]
pub(in super::super) const fn setup_commitment_randomness_distribution_purpose(
    randomness_column_index: usize,
) -> Option<u16> {
    if randomness_column_index < SETUP_COMMITMENT_HIDING_SECRET_WIDTH {
        Some(SETUP_COMMITMENT_HIDING_SECRET_DISTRIBUTION_PURPOSE)
    } else if randomness_column_index < SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        Some(SETUP_COMMITMENT_HIDING_ERROR_DISTRIBUTION_PURPOSE)
    } else {
        None
    }
}

#[cfg(test)]
pub(in super::super) fn setup_commitment_modulus_product() -> BigUint {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| BigUint::from(DATA_PRIMES[*commitment_modulus_index]))
        .product()
}

#[cfg(test)]
pub(in super::super) fn setup_coefficient_fits_commitment_modulus_product(
    coefficient: u128,
) -> bool {
    BigUint::from(coefficient) < setup_commitment_modulus_product()
}

#[cfg(test)]
pub(super) fn setup_coefficients_fit_commitment_modulus_product(coefficients: &[u128]) -> bool {
    let commitment_modulus_product = setup_commitment_modulus_product();
    coefficients
        .iter()
        .all(|coefficient| BigUint::from(*coefficient) < commitment_modulus_product)
}

#[cfg(test)]
pub(super) fn setup_signed_coefficient_fits_centered_commitment_modulus_product(
    coefficient: i128,
) -> bool {
    let Some(coefficient_magnitude) = coefficient.checked_abs() else {
        return false;
    };
    let Ok(coefficient_magnitude) = u128::try_from(coefficient_magnitude) else {
        return false;
    };
    BigUint::from(coefficient_magnitude) * BigUint::from(2_u8) < setup_commitment_modulus_product()
}
