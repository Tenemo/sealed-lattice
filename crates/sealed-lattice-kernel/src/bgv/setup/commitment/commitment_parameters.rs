use super::validation::*;
use super::*;

pub(in super::super) const SETUP_COMMITMENT_MODULE_RANK: usize = 2;
pub(in super::super) const SETUP_COMMITMENT_RANDOMNESS_WIDTH: usize =
    (2 * SETUP_COMMITMENT_MODULE_RANK) + 1;
pub(in super::super) const SETUP_COMMITMENT_ROW_COUNT: usize = SETUP_COMMITMENT_MODULE_RANK + 1;
pub(in super::super) const SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND: i128 = 1;
// Three data-prime limbs set the CRT message-space ceiling; lifted linear
// combinations must stay below their product or binding breaks, which is why the
// carry relation is required above one q_l.
pub(in super::super) const SETUP_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];

pub(in super::super) fn setup_commitment_parameters_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BdlopCommitment",
        "objectVersion": 1,
        "construction": "BDLOP simplified matrix commitment",
        "ring": {
            "coefficientRing": "Z_q[X]/(X^N+1)",
            "ringDegree": POLYNOMIAL_DEGREE,
            "coefficientOrder": "constant-first",
            "ringMultiplication": "negacyclic-ntt-over-selected-bgv-primes"
        },
        "matrixShape": {
            "moduleRank": SETUP_COMMITMENT_MODULE_RANK,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH,
            "commitmentRowCount": SETUP_COMMITMENT_ROW_COUNT,
            "shape": "A1=(A1Prime,Id),A2=(A2Prime,1,0...)"
        },
        "messageEncoding": {
            "source": "per-rns-prime-shamir-coefficient-ring-element",
            "coefficientRange": "0 <= messageCoefficient < sourceRnsPrime",
            "integerEncoding": "crt-lifted-integer-coefficients",
            "commitmentModulusLimbs": setup_commitment_modulus_limb_values(),
            "commitmentModulusProductDecimal": setup_commitment_modulus_product_decimal(),
            "commitmentModulusProductCeilBits": setup_commitment_modulus_product_ceil_bits(),
            "homomorphicNoWrapRule": "linear integer combinations must be strictly below the commitment modulus product before reduction to each commitment limb"
        },
        "openingDistribution": {
            "distribution": "coefficientwise-centered-ternary",
            "coefficientSet": [-1, 0, 1],
            "infinityNormBound": SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
            "randomnessWidth": SETUP_COMMITMENT_RANDOMNESS_WIDTH
        },
        "homomorphism": {
            "addition": "componentwise addition of commitment rows and openings over every commitment modulus limb",
            "scalarMultiplication": "public integer scalar multiplication of commitment rows and openings with explicit no-wrap bound tracking"
        },
        "assumptions": {
            "hiding": "Module-LWE over the selected commitment modulus limbs with short centered-ternary openings",
            "binding": "Module-SIS over the selected commitment modulus limbs for the published BDLOP matrix"
        },
        "serialization": {
            "largeCoefficientMaterial": "binary-chunked-transport",
            "jsonCommitmentRecords": "root-and-sampled-audit-records",
            "coefficientVectorEncoding": "little-endian-u64-per-coefficient"
        }
    }))
}

pub(in super::super) fn setup_commitment_modulus_limb_values() -> Vec<Value> {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": DATA_PRIMES[*commitment_modulus_index],
            })
        })
        .collect()
}

pub(in super::super) fn setup_commitment_modulus_product() -> BigUint {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| BigUint::from(DATA_PRIMES[*commitment_modulus_index]))
        .product()
}

pub(super) fn setup_commitment_modulus_product_decimal() -> String {
    setup_commitment_modulus_product().to_string()
}

pub(in super::super) fn setup_commitment_modulus_product_ceil_bits() -> u32 {
    ceil_log2_big_uint(&setup_commitment_modulus_product())
}

#[cfg(test)]
pub(in super::super) fn setup_coefficient_fits_commitment_modulus_product(
    coefficient: u128,
) -> bool {
    BigUint::from(coefficient) < setup_commitment_modulus_product()
}

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

#[cfg(test)]
pub(super) fn setup_big_signed_coefficient_fits_centered_commitment_modulus_product(
    coefficient: &BigInt,
) -> bool {
    coefficient.magnitude().clone() * BigUint::from(2_u8) < setup_commitment_modulus_product()
}
