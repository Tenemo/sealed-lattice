use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

#[cfg(test)]
use num_bigint::BigInt;
use num_bigint::BigUint;
#[cfg(test)]
use num_traits::ToPrimitive;
use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::coefficient_vector_hash512,
        modular_arithmetic::{add_mod_fast, mul_mod_fast},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{derive_protocol_hash, hash512},
};

use super::{accepted_setup::COLLECTIVE_BGV_SETUP_PROFILE_ID, sampling::reduce_unbiased_u64};

pub(super) const SETUP_COMMITMENT_PROFILE_ID: &str = "SealedLattice-BDLOP-Commitment-v1";
pub(super) const SETUP_COMMITMENT_MODULE_RANK: usize = 2;
pub(super) const SETUP_COMMITMENT_RANDOMNESS_WIDTH: usize = (2 * SETUP_COMMITMENT_MODULE_RANK) + 1;
pub(super) const SETUP_COMMITMENT_ROW_COUNT: usize = SETUP_COMMITMENT_MODULE_RANK + 1;
pub(super) const SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND: i128 = 1;
pub(super) const SETUP_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];

static SETUP_COMMITMENT_MATRIX_NTT_CACHE: OnceLock<Mutex<SetupCommitmentMatrixNttCache>> =
    OnceLock::new();

#[derive(Debug, Default)]
struct SetupCommitmentMatrixNttCache {
    public_matrix_seed_hash: Option<String>,
    entries: HashMap<SetupCommitmentMatrixNttKey, Vec<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SetupCommitmentMatrixNttKey {
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StructuralMatrixPolynomial {
    Zero,
    One,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupCommitmentLimb {
    pub(super) commitment_modulus_index: usize,
    pub(super) modulus: u64,
    pub(super) rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupCommitmentValue {
    pub(super) source_rns_limb_index: usize,
    pub(super) source_message_modulus: u64,
    pub(super) shamir_coefficient_index: u64,
    pub(super) ring_degree: usize,
    pub(super) limbs: Vec<SetupCommitmentLimb>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupCommitmentOpeningVerification {
    pub(super) commitment_root: String,
    pub(super) randomness_infinity_bound: i128,
    pub(super) message_coefficient_bound: u128,
    pub(super) commitment_modulus_product_decimal: String,
    pub(super) commitment_modulus_product_ceil_bits: u32,
}

pub(super) fn setup_commitment_profile_value() -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "BdlopCommitmentProfile",
        "objectVersion": 1,
        "profileId": SETUP_COMMITMENT_PROFILE_ID,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
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
            "binding": "Module-SIS over the selected commitment modulus limbs for the published BDLOP matrix",
            "fullWidthMessageStatus": "claim-accounting-recorded-by-setup-commitment-security-certificate",
            "aggregateOpeningNormStatus": "claim-accounting-recorded-by-setup-commitment-security-certificate",
            "parameterAcceptanceStatus": "claim-bearing-setup-commitment-parameter-accounting-accepted",
            "reviewStatus": "commitment-parameter-certificate-accepted-and-bound-to-accepted-proof-family-verifiers",
            "requiredCertificates": [
                "SetupCommitmentSecurityCertificate",
                "SetupProofAccountingCertificate"
            ]
        },
        "serialization": {
            "largeCoefficientMaterial": "binary-chunked-transport",
            "jsonCommitmentRecords": "root-and-sampled-audit-records",
            "coefficientVectorEncoding": "little-endian-u64-per-coefficient"
        }
    }))
}

pub(super) fn setup_commitment_profile_hash() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupCommitmentProfileHash",
        &setup_commitment_profile_value()?,
    )
}

pub(super) fn setup_commitment_modulus_limb_values() -> Vec<Value> {
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

pub(super) fn setup_commitment_modulus_product() -> BigUint {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| BigUint::from(DATA_PRIMES[*commitment_modulus_index]))
        .product()
}

pub(super) fn setup_commitment_modulus_product_decimal() -> String {
    setup_commitment_modulus_product().to_string()
}

pub(super) fn setup_commitment_modulus_product_ceil_bits() -> u32 {
    ceil_log2_big_uint(&setup_commitment_modulus_product())
}

#[cfg(test)]
pub(super) fn setup_coefficient_fits_commitment_modulus_product(coefficient: u128) -> bool {
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

pub(super) fn setup_commitment_matrix_sampled_entries(
    public_matrix_seed_hash: &str,
    source_rns_limb_indices: &[usize],
    ring_coefficient_positions: &[usize],
) -> CanonicalResult<Vec<Value>> {
    let mut entries = Vec::new();
    for source_rns_limb_index in source_rns_limb_indices {
        for commitment_modulus_index in SETUP_COMMITMENT_MODULUS_LIMB_INDICES {
            let modulus = DATA_PRIMES[commitment_modulus_index];
            for matrix_row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
                for randomness_column_index in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                    for ring_coefficient_position in ring_coefficient_positions {
                        let coefficient_value = setup_commitment_matrix_coefficient(
                            public_matrix_seed_hash,
                            *source_rns_limb_index,
                            commitment_modulus_index,
                            matrix_row_index,
                            randomness_column_index,
                            *ring_coefficient_position,
                            modulus,
                        )?;
                        let coordinate = json!({
                            "rnsLimbIndex": source_rns_limb_index,
                            "rnsPrime": DATA_PRIMES[*source_rns_limb_index],
                            "commitmentModulusIndex": commitment_modulus_index,
                            "commitmentModulus": modulus,
                            "matrixRowIndex": matrix_row_index,
                            "randomnessColumnIndex": randomness_column_index,
                            "ringCoefficientPosition": ring_coefficient_position,
                        });
                        let entry_derivation_hash = setup_commitment_matrix_entry_hash(
                            public_matrix_seed_hash,
                            &coordinate,
                            coefficient_value,
                        )?;
                        entries.push(json!({
                            "coordinate": coordinate,
                            "coefficientValue": coefficient_value,
                            "entryDerivationHash": entry_derivation_hash,
                        }));
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(test)]
pub(super) fn verify_setup_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_column: &[Vec<i128>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    verify_setup_commitment_opening_with_message_bound(
        public_matrix_seed_hash,
        expected_commitment,
        message_coefficients,
        randomness_by_column,
        randomness_infinity_bound,
        Some(u128::from(expected_commitment.source_message_modulus)),
    )
}

#[cfg(test)]
pub(super) fn verify_setup_lifted_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_column: &[Vec<i128>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    verify_setup_commitment_opening_with_message_bound(
        public_matrix_seed_hash,
        expected_commitment,
        message_coefficients,
        randomness_by_column,
        randomness_infinity_bound,
        None,
    )
}

#[cfg(test)]
pub(super) fn verify_setup_signed_lifted_commitment_opening(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[i128],
    randomness_by_column: &[Vec<i128>],
    randomness_infinity_bound: i128,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    validate_signed_message_coefficients(message_coefficients, expected_commitment.ring_degree)?;
    validate_randomness_by_column(
        randomness_by_column,
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
        expected_commitment.source_message_modulus,
        expected_commitment.shamir_coefficient_index,
        message_coefficients,
        randomness_by_column,
        expected_commitment.ring_degree,
    )?;
    if &computed_commitment != expected_commitment {
        return Err(invalid_commitment_input(
            "signed commitment opening does not reproduce the published commitment",
        ));
    }

    Ok(SetupCommitmentOpeningVerification {
        commitment_root: setup_commitment_root(&computed_commitment)?,
        randomness_infinity_bound,
        message_coefficient_bound,
        commitment_modulus_product_decimal: setup_commitment_modulus_product_decimal(),
        commitment_modulus_product_ceil_bits: setup_commitment_modulus_product_ceil_bits(),
    })
}

pub(super) fn linear_combination_setup_commitments(
    terms: &[(&SetupCommitmentValue, u128)],
) -> CanonicalResult<SetupCommitmentValue> {
    let Some((first_commitment, _)) = terms.first() else {
        return Err(invalid_commitment_input(
            "at least one commitment is required for a linear combination",
        ));
    };
    let mut combined_commitment = (*first_commitment).clone();
    for limb in &mut combined_commitment.limbs {
        for row in &mut limb.rows {
            row.fill(0);
        }
    }

    for (commitment, scalar) in terms {
        validate_same_commitment_domain(first_commitment, commitment)?;
        for (combined_limb, term_limb) in combined_commitment
            .limbs
            .iter_mut()
            .zip(commitment.limbs.iter())
        {
            let modulus = combined_limb.modulus;
            let scalar_residue = u64::try_from(*scalar % u128::from(modulus)).map_err(|_| {
                invalid_commitment_input("commitment linear-combination scalar does not fit u64")
            })?;
            for (combined_row, term_row) in combined_limb.rows.iter_mut().zip(term_limb.rows.iter())
            {
                for (combined_value, term_value) in combined_row.iter_mut().zip(term_row.iter()) {
                    *combined_value = add_mod_fast(
                        *combined_value,
                        mul_mod_fast(*term_value, scalar_residue, modulus),
                        modulus,
                    );
                }
            }
        }
    }

    Ok(combined_commitment)
}

pub(super) fn add_scaled_setup_commitment_in_place(
    target_commitment: &mut SetupCommitmentValue,
    term_commitment: &SetupCommitmentValue,
    scalar: u128,
) -> CanonicalResult<()> {
    validate_same_commitment_domain(target_commitment, term_commitment)?;
    for (target_limb, term_limb) in target_commitment
        .limbs
        .iter_mut()
        .zip(term_commitment.limbs.iter())
    {
        let modulus = target_limb.modulus;
        let scalar_residue = u64::try_from(scalar % u128::from(modulus)).map_err(|_| {
            invalid_commitment_input("commitment linear-combination scalar does not fit u64")
        })?;
        for (target_row, term_row) in target_limb.rows.iter_mut().zip(term_limb.rows.iter()) {
            for (target_value, term_value) in target_row.iter_mut().zip(term_row.iter()) {
                *target_value = add_mod_fast(
                    *target_value,
                    mul_mod_fast(*term_value, scalar_residue, modulus),
                    modulus,
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
fn verify_setup_commitment_opening_with_message_bound(
    public_matrix_seed_hash: &str,
    expected_commitment: &SetupCommitmentValue,
    message_coefficients: &[u128],
    randomness_by_column: &[Vec<i128>],
    randomness_infinity_bound: i128,
    message_exclusive_bound: Option<u128>,
) -> CanonicalResult<SetupCommitmentOpeningVerification> {
    validate_message_coefficients(
        message_coefficients,
        message_exclusive_bound,
        expected_commitment.ring_degree,
    )?;
    validate_randomness_by_column(
        randomness_by_column,
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
        expected_commitment.source_message_modulus,
        expected_commitment.shamir_coefficient_index,
        message_coefficients,
        randomness_by_column,
        expected_commitment.ring_degree,
    )?;
    if &computed_commitment != expected_commitment {
        return Err(invalid_commitment_input(
            "commitment opening does not reproduce the published commitment",
        ));
    }

    Ok(SetupCommitmentOpeningVerification {
        commitment_root: setup_commitment_root(&computed_commitment)?,
        randomness_infinity_bound,
        message_coefficient_bound,
        commitment_modulus_product_decimal: setup_commitment_modulus_product_decimal(),
        commitment_modulus_product_ceil_bits: setup_commitment_modulus_product_ceil_bits(),
    })
}

fn validate_same_commitment_domain(
    first_commitment: &SetupCommitmentValue,
    commitment: &SetupCommitmentValue,
) -> CanonicalResult<()> {
    if first_commitment.source_rns_limb_index != commitment.source_rns_limb_index
        || first_commitment.source_message_modulus != commitment.source_message_modulus
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

pub(super) fn setup_commitment_root(commitment: &SetupCommitmentValue) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupCommitmentRoot",
        &setup_commitment_root_payload(commitment),
    )
}

fn setup_commitment_chunk_root(
    commitment: &SetupCommitmentValue,
    commitment_root: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "VssCoefficientCommitmentRoot",
        &json!({
            "objectType": "VssCoefficientCommitmentChunkRoot",
            "objectVersion": 1,
            "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
            "commitmentRoot": commitment_root,
            "commitmentLimbs": commitment.limbs.iter().map(|limb| {
                json!({
                    "commitmentModulusIndex": limb.commitment_modulus_index,
                    "modulus": limb.modulus,
                    "rowCoefficientHash512": limb.rows.iter().map(|row| {
                        coefficient_vector_hash512(
                            row,
                            "sealed-lattice-bdlop-commitment/row-coefficients-v1",
                        )
                    }).collect::<Vec<_>>()
                })
            }).collect::<Vec<_>>()
        }),
    )
}

fn public_commitment_coefficient_vector_hash512(commitment: &SetupCommitmentValue) -> String {
    let coefficients = commitment
        .limbs
        .iter()
        .flat_map(|limb| limb.rows.iter())
        .flat_map(|row| row.iter().copied())
        .collect::<Vec<_>>();

    coefficient_vector_hash512(
        &coefficients,
        "sealed-lattice-bdlop-commitment/public-commitment-coefficients-v1",
    )
}

pub(super) fn setup_commitment_full_value(commitment: &SetupCommitmentValue) -> Value {
    json!({
        "objectType": "SetupCommitment",
        "objectVersion": 1,
        "profileId": SETUP_COMMITMENT_PROFILE_ID,
        "sourceRnsLimbIndex": commitment.source_rns_limb_index,
        "sourceMessageModulus": commitment.source_message_modulus,
        "shamirCoefficientIndex": commitment.shamir_coefficient_index,
        "ringDegree": commitment.ring_degree,
        "commitmentLimbs": commitment.limbs.iter().map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rows": limb.rows,
            })
        }).collect::<Vec<_>>()
    })
}

pub(super) fn parse_setup_commitment_full_value(
    value: &Value,
) -> CanonicalResult<SetupCommitmentValue> {
    if value.get("objectType").and_then(Value::as_str) != Some("SetupCommitment") {
        return Err(invalid_commitment_input(
            "setup commitment objectType must be SetupCommitment",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_commitment_input(
            "setup commitment objectVersion must be 1",
        ));
    }
    if value.get("profileId").and_then(Value::as_str) != Some(SETUP_COMMITMENT_PROFILE_ID) {
        return Err(invalid_commitment_input(
            "setup commitment profileId does not match the accepted commitment profile",
        ));
    }
    let source_rns_limb_index = read_usize(value, "sourceRnsLimbIndex")?;
    let source_message_modulus = read_u64(value, "sourceMessageModulus")?;
    validate_source_rns_limb(source_rns_limb_index, source_message_modulus)?;
    let shamir_coefficient_index = read_u64(value, "shamirCoefficientIndex")?;
    let ring_degree = read_usize(value, "ringDegree")?;
    validate_ring_degree(ring_degree)?;
    let commitment_limb_values = value
        .get("commitmentLimbs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_commitment_input("setup commitment must include commitmentLimbs"))?;
    if commitment_limb_values.len() != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(invalid_commitment_input(
            "setup commitment must include every selected commitment modulus limb",
        ));
    }

    let mut seen_limb_indices = Vec::new();
    let mut limbs = Vec::with_capacity(commitment_limb_values.len());
    for limb_value in commitment_limb_values {
        let commitment_modulus_index = read_usize(limb_value, "commitmentModulusIndex")?;
        if !SETUP_COMMITMENT_MODULUS_LIMB_INDICES.contains(&commitment_modulus_index) {
            return Err(invalid_commitment_input(
                "setup commitment limb uses a modulus outside the accepted commitment profile",
            ));
        }
        if seen_limb_indices.contains(&commitment_modulus_index) {
            return Err(invalid_commitment_input(
                "setup commitment limbs must have distinct commitmentModulusIndex values",
            ));
        }
        seen_limb_indices.push(commitment_modulus_index);
        let modulus = read_u64(limb_value, "modulus")?;
        if DATA_PRIMES.get(commitment_modulus_index) != Some(&modulus) {
            return Err(invalid_commitment_input(
                "setup commitment limb modulus does not match the selected commitment modulus",
            ));
        }
        let row_values = limb_value
            .get("rows")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_commitment_input("setup commitment limb must include rows"))?;
        if row_values.len() != SETUP_COMMITMENT_ROW_COUNT {
            return Err(invalid_commitment_input(
                "setup commitment limb must include the selected commitment row count",
            ));
        }
        let rows = row_values
            .iter()
            .map(|row_value| read_residue_row(row_value, ring_degree, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index,
            modulus,
            rows,
        });
    }
    limbs.sort_by_key(|limb| limb.commitment_modulus_index);

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

fn setup_commitment_root_payload(commitment: &SetupCommitmentValue) -> Value {
    json!({
        "objectType": "SetupCommitment",
        "objectVersion": 1,
        "profileId": SETUP_COMMITMENT_PROFILE_ID,
        "sourceRnsLimbIndex": commitment.source_rns_limb_index,
        "sourceMessageModulus": commitment.source_message_modulus,
        "shamirCoefficientIndex": commitment.shamir_coefficient_index,
        "ringDegree": commitment.ring_degree,
        "commitmentLimbs": commitment.limbs.iter().map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rowCoefficientHash512": limb.rows.iter().map(|row| {
                    coefficient_vector_hash512(
                        row,
                        "sealed-lattice-bdlop-commitment/row-coefficients-v1",
                    )
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    })
}

fn read_u64(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_commitment_input(format!("{field_name} must be a non-negative integer"))
        })
}

fn read_usize(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let value = read_u64(value, field_name)?;
    usize::try_from(value)
        .map_err(|_| invalid_commitment_input(format!("{field_name} does not fit usize")))
}

fn read_unsigned_message_coefficients(
    value: &Value,
    field_name: &str,
) -> CanonicalResult<Vec<u128>> {
    let coefficient_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_commitment_input(format!(
                "{field_name} must be an array of unsigned integers"
            ))
        })?;
    coefficient_values
        .iter()
        .enumerate()
        .map(|(coefficient_index, coefficient_value)| {
            coefficient_value.as_u64().map(u128::from).ok_or_else(|| {
                invalid_commitment_input(format!(
                    "{field_name}[{coefficient_index}] must be a non-negative integer"
                ))
            })
        })
        .collect()
}

fn read_randomness_by_column(value: &Value, field_name: &str) -> CanonicalResult<Vec<Vec<i128>>> {
    let column_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_commitment_input(format!("{field_name} must be an array of columns"))
        })?;
    column_values
        .iter()
        .enumerate()
        .map(|(column_index, column_value)| {
            let coefficient_values = column_value.as_array().ok_or_else(|| {
                invalid_commitment_input(format!(
                    "{field_name}[{column_index}] must be an array of signed integers"
                ))
            })?;
            coefficient_values
                .iter()
                .enumerate()
                .map(|(coefficient_index, coefficient_value)| {
                    coefficient_value.as_i64().map(i128::from).ok_or_else(|| {
                        invalid_commitment_input(format!(
                            "{field_name}[{column_index}][{coefficient_index}] must be a signed integer"
                        ))
                    })
                })
                .collect()
        })
        .collect()
}

fn read_residue_row(value: &Value, ring_degree: usize, modulus: u64) -> CanonicalResult<Vec<u64>> {
    let row = value
        .as_array()
        .ok_or_else(|| invalid_commitment_input("setup commitment row must be an array"))?;
    if row.len() != ring_degree {
        return Err(invalid_commitment_input(
            "setup commitment row length must match the ring degree",
        ));
    }
    row.iter()
        .map(|coefficient| {
            let coefficient = coefficient.as_u64().ok_or_else(|| {
                invalid_commitment_input("setup commitment row coefficients must be integers")
            })?;
            if coefficient >= modulus {
                return Err(invalid_commitment_input(
                    "setup commitment row coefficient is outside the commitment modulus",
                ));
            }
            Ok(coefficient)
        })
        .collect()
}

fn compute_setup_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index, source_message_modulus)?;
    validate_ring_degree(ring_degree)?;
    validate_message_coefficients(message_coefficients, None, ring_degree)?;
    validate_randomness_shape(randomness_by_column, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        source_rns_limb_index,
        message_coefficients,
        randomness_by_column,
        ring_degree,
        |coefficient, modulus| {
            u64::try_from(*coefficient % u128::from(modulus)).map_err(|_| {
                invalid_commitment_input("message coefficient residue does not fit u64")
            })
        },
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
fn compute_setup_signed_lifted_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
    message_coefficients: &[i128],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index, source_message_modulus)?;
    validate_ring_degree(ring_degree)?;
    validate_signed_message_coefficients(message_coefficients, ring_degree)?;
    validate_randomness_shape(randomness_by_column, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        source_rns_limb_index,
        message_coefficients,
        randomness_by_column,
        ring_degree,
        |coefficient, modulus| centered_integer_to_residue(*coefficient, modulus),
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
fn compute_setup_big_signed_lifted_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
    message_coefficients: &[BigInt],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index, source_message_modulus)?;
    validate_ring_degree(ring_degree)?;
    validate_big_signed_message_coefficients(message_coefficients, ring_degree)?;
    validate_randomness_shape(randomness_by_column, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        source_rns_limb_index,
        message_coefficients,
        randomness_by_column,
        ring_degree,
        centered_big_integer_to_residue,
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
pub(super) fn compute_setup_big_signed_lifted_commitment(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
    message_coefficients: &[BigInt],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    compute_setup_big_signed_lifted_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_column,
        ring_degree,
    )
}

fn compute_setup_commitment_limbs<MessageCoefficient>(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    message_coefficients: &[MessageCoefficient],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
    message_residue: impl Fn(&MessageCoefficient, u64) -> CanonicalResult<u64>,
) -> CanonicalResult<Vec<SetupCommitmentLimb>> {
    let mut limbs = Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
    for commitment_modulus_index in SETUP_COMMITMENT_MODULUS_LIMB_INDICES {
        let modulus = DATA_PRIMES[commitment_modulus_index];
        let message_residues = message_coefficients
            .iter()
            .map(|coefficient| message_residue(coefficient, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let randomness_residues = randomness_by_column
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|coefficient| centered_integer_to_residue(*coefficient, modulus))
                    .collect::<CanonicalResult<Vec<_>>>()
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let mut randomness_ntts: Vec<Option<Vec<u64>>> =
            vec![None; SETUP_COMMITMENT_RANDOMNESS_WIDTH];
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
                if randomness_ntts[randomness_column_index].is_none() {
                    randomness_ntts[randomness_column_index] = Some(forward_negacyclic_ntt(
                        &randomness_residues[randomness_column_index],
                        modulus,
                    )?);
                }
                let matrix_ntt = setup_commitment_matrix_ntt(
                    public_matrix_seed_hash,
                    source_rns_limb_index,
                    commitment_modulus_index,
                    matrix_row_index,
                    randomness_column_index,
                    ring_degree,
                    modulus,
                )?;
                let randomness_ntt = randomness_ntts[randomness_column_index]
                    .as_ref()
                    .expect("randomness NTT was populated before use");
                for ((accumulated_value, matrix_value), randomness_value) in row_ntt
                    .iter_mut()
                    .zip(matrix_ntt.iter())
                    .zip(randomness_ntt.iter())
                {
                    *accumulated_value = add_mod_fast(
                        *accumulated_value,
                        mul_mod_fast(*matrix_value, *randomness_value, modulus),
                        modulus,
                    );
                }
                has_sampled_matrix_product = true;
            }

            let mut row_accumulator = if has_sampled_matrix_product {
                inverse_negacyclic_ntt(&row_ntt, modulus)?
            } else {
                vec![0_u64; ring_degree]
            };
            for (randomness_column_index, randomness_column) in
                randomness_residues.iter().enumerate()
            {
                match structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index) {
                    Some(StructuralMatrixPolynomial::One) => {
                        for (accumulated_value, randomness_value) in
                            row_accumulator.iter_mut().zip(randomness_column.iter())
                        {
                            *accumulated_value =
                                add_mod_fast(*accumulated_value, *randomness_value, modulus);
                        }
                    }
                    Some(StructuralMatrixPolynomial::Zero) | None => {}
                }
            }
            if matrix_row_index == SETUP_COMMITMENT_MODULE_RANK {
                for (accumulated_value, message_value) in
                    row_accumulator.iter_mut().zip(message_residues.iter())
                {
                    *accumulated_value = add_mod_fast(*accumulated_value, *message_value, modulus);
                }
            }
            rows.push(row_accumulator);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index,
            modulus,
            rows,
        });
    }

    Ok(limbs)
}

pub(crate) fn compute_setup_commitment_from_opening_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_commitment_request_fields(request)?;
    let public_matrix_seed_hash = request
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_commitment_input("publicMatrixSeedHash must be a string"))?;
    let source_rns_limb_index = read_usize(request, "sourceRnsLimbIndex")?;
    let source_message_modulus = read_u64(request, "sourceMessageModulus")?;
    let shamir_coefficient_index = read_u64(request, "shamirCoefficientIndex")?;
    let ring_degree = read_usize(request, "ringDegree")?;
    let message_coefficients = read_unsigned_message_coefficients(request, "messageCoefficients")?;
    let randomness_by_column = read_randomness_by_column(request, "randomnessByColumn")?;

    let commitment = compute_setup_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        &message_coefficients,
        &randomness_by_column,
        ring_degree,
    )?;
    let commitment_root = setup_commitment_root(&commitment)?;
    let commitment_chunk_root = setup_commitment_chunk_root(&commitment, &commitment_root)?;
    let coefficient_vector_hash = public_commitment_coefficient_vector_hash512(&commitment);

    Ok(json!({
        "ok": true,
        "operation": "computeSetupCommitmentFromOpening",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitment": setup_commitment_full_value(&commitment),
        "commitmentRoot": commitment_root,
        "commitmentChunkRoot": commitment_chunk_root,
        "coefficientVectorHash512": coefficient_vector_hash,
    }))
}

#[cfg(test)]
pub(super) fn compute_setup_commitment_for_tests(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    source_message_modulus: u64,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    compute_setup_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        source_message_modulus,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_column,
        ring_degree,
    )
}

pub(super) fn setup_commitment_matrix_polynomial(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut coefficients = Vec::with_capacity(ring_degree);
    for ring_coefficient_position in 0..ring_degree {
        coefficients.push(setup_commitment_matrix_coefficient(
            public_matrix_seed_hash,
            source_rns_limb_index,
            commitment_modulus_index,
            matrix_row_index,
            randomness_column_index,
            ring_coefficient_position,
            modulus,
        )?);
    }

    Ok(coefficients)
}

fn setup_commitment_matrix_ntt(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let key = SetupCommitmentMatrixNttKey {
        source_rns_limb_index,
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
        ring_degree,
        modulus,
    };
    let cache_mutex = SETUP_COMMITMENT_MATRIX_NTT_CACHE
        .get_or_init(|| Mutex::new(SetupCommitmentMatrixNttCache::default()));
    {
        let mut cache = cache_mutex
            .lock()
            .map_err(|_| invalid_commitment_input("setup commitment matrix cache poisoned"))?;
        if cache.public_matrix_seed_hash.as_deref() != Some(public_matrix_seed_hash) {
            cache.public_matrix_seed_hash = Some(public_matrix_seed_hash.to_string());
            cache.entries.clear();
        }
        if let Some(cached_ntt) = cache.entries.get(&key) {
            return Ok(cached_ntt.clone());
        }
    }

    let matrix_polynomial = setup_commitment_matrix_polynomial(
        public_matrix_seed_hash,
        source_rns_limb_index,
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
        ring_degree,
        modulus,
    )?;
    let matrix_ntt = forward_negacyclic_ntt(&matrix_polynomial, modulus)?;
    {
        let mut cache = cache_mutex
            .lock()
            .map_err(|_| invalid_commitment_input("setup commitment matrix cache poisoned"))?;
        if cache.public_matrix_seed_hash.as_deref() != Some(public_matrix_seed_hash) {
            cache.public_matrix_seed_hash = Some(public_matrix_seed_hash.to_string());
            cache.entries.clear();
        }
        cache.entries.insert(key, matrix_ntt.clone());
    }

    Ok(matrix_ntt)
}

// Coefficient-form matrix polynomial through the process-wide NTT cache: the
// expensive hash sampling happens once per coordinate set and seed.
pub(super) fn setup_commitment_matrix_coefficients_cached(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let matrix_ntt = setup_commitment_matrix_ntt(
        public_matrix_seed_hash,
        source_rns_limb_index,
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
        ring_degree,
        modulus,
    )?;

    inverse_negacyclic_ntt(&matrix_ntt, modulus)
}

fn setup_commitment_matrix_coefficient(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_coefficient_position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    validate_matrix_coordinate(
        source_rns_limb_index,
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
        ring_coefficient_position,
    )?;
    if let Some(structural_coefficient) = structural_matrix_coefficient(
        matrix_row_index,
        randomness_column_index,
        ring_coefficient_position,
    ) {
        return Ok(structural_coefficient % modulus);
    }

    sample_commitment_matrix_residue(
        public_matrix_seed_hash,
        source_rns_limb_index,
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
        ring_coefficient_position,
        modulus,
    )
}

fn structural_matrix_coefficient(
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_coefficient_position: usize,
) -> Option<u64> {
    if matrix_row_index < SETUP_COMMITMENT_MODULE_RANK
        && randomness_column_index > SETUP_COMMITMENT_MODULE_RANK
    {
        let identity_column_index = randomness_column_index - SETUP_COMMITMENT_MODULE_RANK - 1;
        let is_identity_entry = identity_column_index == matrix_row_index;
        return Some(u64::from(
            is_identity_entry && ring_coefficient_position == 0,
        ));
    }
    if matrix_row_index == SETUP_COMMITMENT_MODULE_RANK
        && randomness_column_index >= SETUP_COMMITMENT_MODULE_RANK
    {
        let is_message_blinding_column = randomness_column_index == SETUP_COMMITMENT_MODULE_RANK;
        return Some(u64::from(
            is_message_blinding_column && ring_coefficient_position == 0,
        ));
    }

    None
}

pub(super) fn structural_matrix_polynomial_kind(
    matrix_row_index: usize,
    randomness_column_index: usize,
) -> Option<StructuralMatrixPolynomial> {
    if matrix_row_index < SETUP_COMMITMENT_MODULE_RANK
        && randomness_column_index > SETUP_COMMITMENT_MODULE_RANK
    {
        let identity_column_index = randomness_column_index - SETUP_COMMITMENT_MODULE_RANK - 1;
        if identity_column_index == matrix_row_index {
            return Some(StructuralMatrixPolynomial::One);
        }

        return Some(StructuralMatrixPolynomial::Zero);
    }
    if matrix_row_index == SETUP_COMMITMENT_MODULE_RANK
        && randomness_column_index >= SETUP_COMMITMENT_MODULE_RANK
    {
        if randomness_column_index == SETUP_COMMITMENT_MODULE_RANK {
            return Some(StructuralMatrixPolynomial::One);
        }

        return Some(StructuralMatrixPolynomial::Zero);
    }

    None
}

fn sample_commitment_matrix_residue(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_coefficient_position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    let source_limb_text = source_rns_limb_index.to_string();
    let commitment_modulus_text = commitment_modulus_index.to_string();
    let matrix_row_text = matrix_row_index.to_string();
    let randomness_column_text = randomness_column_index.to_string();
    let position_text = ring_coefficient_position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    loop {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bdlop-commitment/matrix-coefficient-v1",
            &[
                public_matrix_seed_hash.as_bytes(),
                source_limb_text.as_bytes(),
                commitment_modulus_text.as_bytes(),
                matrix_row_text.as_bytes(),
                randomness_column_text.as_bytes(),
                position_text.as_bytes(),
                modulus_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        for chunk in output.chunks_exact(8) {
            let mut word = [0_u8; 8];
            word.copy_from_slice(chunk);
            if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), modulus) {
                return Ok(reduced_value);
            }
        }
        block_index = block_index
            .checked_add(1)
            .ok_or_else(|| invalid_commitment_input("matrix sampling block index overflow"))?;
    }
}

fn setup_commitment_matrix_entry_hash(
    public_matrix_seed_hash: &str,
    coordinate: &Value,
    coefficient_value: u64,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupPublicDerivationRoot",
        &json!({
            "objectType": "SetupCommitmentMatrixEntryDerivation",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coordinate": coordinate,
            "coefficientValue": coefficient_value,
        }),
    )
}

fn centered_integer_to_residue(value: i128, modulus: u64) -> CanonicalResult<u64> {
    let modulus_wide = i128::from(modulus);
    let residue = value.rem_euclid(modulus_wide);
    u64::try_from(residue)
        .map_err(|_| invalid_commitment_input("centered residue does not fit u64"))
}

#[cfg(test)]
fn centered_big_integer_to_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_big = BigInt::from(modulus);
    let residue = ((value % &modulus_big) + &modulus_big) % &modulus_big;
    residue
        .to_u64()
        .ok_or_else(|| invalid_commitment_input("centered residue does not fit u64"))
}

fn validate_message_coefficients(
    message_coefficients: &[u128],
    exclusive_bound: Option<u128>,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment message coefficient count must match the ring degree",
        ));
    }
    if let Some(exclusive_bound) = exclusive_bound
        && message_coefficients
            .iter()
            .any(|coefficient| *coefficient >= exclusive_bound)
    {
        return Err(invalid_commitment_input(
            "commitment message coefficient is outside the declared integer range",
        ));
    }
    if !setup_coefficients_fit_commitment_modulus_product(message_coefficients) {
        return Err(invalid_commitment_input(
            "commitment message coefficient would wrap in the CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn validate_signed_message_coefficients(
    message_coefficients: &[i128],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "signed commitment message coefficient count must match the ring degree",
        ));
    }
    if !message_coefficients.iter().all(|coefficient| {
        setup_signed_coefficient_fits_centered_commitment_modulus_product(*coefficient)
    }) {
        return Err(invalid_commitment_input(
            "signed commitment message coefficient would wrap in the centered CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn validate_big_signed_message_coefficients(
    message_coefficients: &[BigInt],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if message_coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "signed commitment message coefficient count must match the ring degree",
        ));
    }
    if !message_coefficients
        .iter()
        .all(setup_big_signed_coefficient_fits_centered_commitment_modulus_product)
    {
        return Err(invalid_commitment_input(
            "signed commitment message coefficient would wrap in the centered CRT commitment modulus",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn signed_message_coefficient_magnitude_bound(
    message_coefficients: &[i128],
) -> CanonicalResult<u128> {
    message_coefficients
        .iter()
        .map(|coefficient| {
            let magnitude = coefficient.checked_abs().ok_or_else(|| {
                invalid_commitment_input(
                    "signed commitment message coefficient absolute value overflowed",
                )
            })?;
            u128::try_from(magnitude).map_err(|_| {
                invalid_commitment_input(
                    "signed commitment message coefficient magnitude does not fit u128",
                )
            })
        })
        .try_fold(0_u128, |bound, magnitude| {
            magnitude.map(|magnitude| bound.max(magnitude))
        })
}

fn ceil_log2_big_uint(value: &BigUint) -> u32 {
    if value <= &BigUint::from(1_u8) {
        return 0;
    }
    let previous = value - BigUint::from(1_u8);
    u32::try_from(previous.bits()).expect("setup commitment modulus bit length fits u32")
}

#[cfg(test)]
fn validate_randomness_by_column(
    randomness_by_column: &[Vec<i128>],
    infinity_bound: i128,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if infinity_bound < 0 {
        return Err(invalid_commitment_input(
            "commitment randomness bound must be non-negative",
        ));
    }
    validate_randomness_shape(randomness_by_column, ring_degree)?;
    for randomness_column in randomness_by_column {
        if randomness_column
            .iter()
            .any(|coefficient| coefficient.abs() > infinity_bound)
        {
            return Err(invalid_commitment_input(
                "commitment randomness coefficient exceeds the opening bound",
            ));
        }
    }

    Ok(())
}

fn validate_randomness_shape(
    randomness_by_column: &[Vec<i128>],
    ring_degree: usize,
) -> CanonicalResult<()> {
    if randomness_by_column.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment opening must contain the selected randomness width",
        ));
    }
    for randomness_column in randomness_by_column {
        if randomness_column.len() != ring_degree {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "commitment randomness column coefficient count must match the ring degree",
            ));
        }
    }

    Ok(())
}

fn validate_source_rns_limb(
    source_rns_limb_index: usize,
    source_message_modulus: u64,
) -> CanonicalResult<()> {
    if DATA_PRIMES.get(source_rns_limb_index) != Some(&source_message_modulus) {
        return Err(invalid_commitment_input(
            "commitment source RNS limb does not match the selected Q_share prime list",
        ));
    }

    Ok(())
}

fn validate_ring_degree(ring_degree: usize) -> CanonicalResult<()> {
    if ring_degree == 0
        || ring_degree > POLYNOMIAL_DEGREE
        || !ring_degree.is_power_of_two()
        || !POLYNOMIAL_DEGREE.is_multiple_of(ring_degree)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "commitment ring degree must be a power-of-two divisor of the selected BGV ring degree",
        ));
    }

    Ok(())
}

fn validate_matrix_coordinate(
    source_rns_limb_index: usize,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_coefficient_position: usize,
) -> CanonicalResult<()> {
    if source_rns_limb_index >= DATA_PRIMES.len() {
        return Err(invalid_commitment_input(
            "commitment matrix source RNS limb is outside Q_share",
        ));
    }
    if !SETUP_COMMITMENT_MODULUS_LIMB_INDICES.contains(&commitment_modulus_index) {
        return Err(invalid_commitment_input(
            "commitment matrix modulus limb is outside the commitment profile",
        ));
    }
    if matrix_row_index >= SETUP_COMMITMENT_ROW_COUNT {
        return Err(invalid_commitment_input(
            "commitment matrix row is outside the selected BDLOP shape",
        ));
    }
    if randomness_column_index >= SETUP_COMMITMENT_RANDOMNESS_WIDTH {
        return Err(invalid_commitment_input(
            "commitment matrix column is outside the selected BDLOP shape",
        ));
    }
    if ring_coefficient_position >= POLYNOMIAL_DEGREE {
        return Err(invalid_commitment_input(
            "commitment matrix ring coefficient is outside the selected ring degree",
        ));
    }

    Ok(())
}

fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() != 128 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be a lowercase Hash512 hex string"),
        ));
    }
    if !hash
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} must be lowercase hexadecimal"),
        ));
    }

    Ok(())
}

fn reject_unexpected_commitment_request_fields(request: &Value) -> CanonicalResult<()> {
    let Some(object) = request.as_object() else {
        return Err(invalid_commitment_input(
            "setup commitment request must be an object",
        ));
    };
    for field_name in object.keys() {
        if ![
            "command",
            "publicMatrixSeedHash",
            "sourceRnsLimbIndex",
            "sourceMessageModulus",
            "shamirCoefficientIndex",
            "messageCoefficients",
            "randomnessByColumn",
            "ringDegree",
        ]
        .contains(&field_name.as_str())
        {
            return Err(invalid_commitment_input(format!(
                "setup commitment request contains unexpected field {field_name}"
            )));
        }
    }

    Ok(())
}

fn invalid_commitment_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use serde_json::json;

    use super::{
        SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, compute_setup_commitment_for_degree,
        compute_setup_commitment_from_opening_request,
        compute_setup_signed_lifted_commitment_for_degree,
        setup_coefficient_fits_commitment_modulus_product, setup_commitment_profile_hash,
        setup_commitment_profile_value, setup_commitment_root, verify_setup_commitment_opening,
        verify_setup_lifted_commitment_opening, verify_setup_signed_lifted_commitment_opening,
    };
    use crate::{
        bgv::{
            modular_arithmetic::{add_mod_fast, mul_mod_fast},
            profile::DATA_PRIMES,
        },
        encoding::CanonicalResult,
    };

    const TEST_RING_DEGREE: usize = 8;

    #[test]
    fn commitment_profile_binds_crt_lifted_message_space() {
        let profile = setup_commitment_profile_value().expect("profile");

        assert_eq!(profile["objectType"], "BdlopCommitmentProfile");
        assert_eq!(
            profile["messageEncoding"]["integerEncoding"],
            "crt-lifted-integer-coefficients"
        );
        assert_eq!(
            profile["matrixShape"]["moduleRank"],
            SETUP_COMMITMENT_MODULE_RANK
        );
        assert!(
            profile["messageEncoding"]["commitmentModulusProductDecimal"]
                .as_str()
                .expect("product decimal")
                .parse::<BigUint>()
                .expect("product should parse")
                > BigUint::from(DATA_PRIMES[0]) * BigUint::from(1000_u16)
        );
        assert_eq!(setup_commitment_profile_hash().expect("hash").len(), 128);
    }

    #[test]
    fn commitment_opening_verifies_and_rejects_tampering() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('a');
        let message = message_coefficients();
        let randomness = randomness_columns(SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND);
        let commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
            2,
            &message,
            &randomness,
            TEST_RING_DEGREE,
        )?;

        let verification = verify_setup_commitment_opening(
            &public_matrix_seed_hash,
            &commitment,
            &message,
            &randomness,
            SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        )?;

        assert_eq!(
            verification.commitment_root,
            setup_commitment_root(&commitment)?
        );
        assert_eq!(verification.message_coefficient_bound, u128::from(34_u64));

        let mut tampered_commitment = commitment.clone();
        tampered_commitment.limbs[0].rows[0][0] =
            (tampered_commitment.limbs[0].rows[0][0] + 1) % tampered_commitment.limbs[0].modulus;
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &tampered_commitment,
                &message,
                &randomness,
                SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
            )
            .is_err()
        );

        let mut out_of_range_message = message;
        out_of_range_message[3] = u128::from(DATA_PRIMES[0]);
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &commitment,
                &out_of_range_message,
                &randomness,
                SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn commitment_command_computes_canonical_roots() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('e');
        let message = message_coefficients();
        let randomness = randomness_columns(1);
        let response = compute_setup_commitment_from_opening_request(&json!({
            "command": "ComputeSetupCommitmentFromOpening",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceRnsLimbIndex": 0,
            "sourceMessageModulus": DATA_PRIMES[0],
            "shamirCoefficientIndex": 1,
            "messageCoefficients": message,
            "randomnessByColumn": randomness,
            "ringDegree": TEST_RING_DEGREE,
        }))?;

        assert_eq!(response["ok"], true);
        assert_eq!(response["operation"], "computeSetupCommitmentFromOpening");
        assert_eq!(
            response["commitmentRoot"]
                .as_str()
                .expect("commitment root")
                .len(),
            128
        );
        assert_eq!(
            response["commitmentChunkRoot"]
                .as_str()
                .expect("commitment chunk root")
                .len(),
            128
        );
        assert_eq!(
            response["coefficientVectorHash512"]
                .as_str()
                .expect("coefficient vector hash")
                .len(),
            128
        );

        Ok(())
    }

    #[test]
    fn commitment_command_rejects_extra_fields_and_wrong_source_prime() {
        let public_matrix_seed_hash = valid_hash('f');
        let valid_request = json!({
            "command": "ComputeSetupCommitmentFromOpening",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceRnsLimbIndex": 0,
            "sourceMessageModulus": DATA_PRIMES[0],
            "shamirCoefficientIndex": 1,
            "messageCoefficients": message_coefficients(),
            "randomnessByColumn": randomness_columns(1),
            "ringDegree": TEST_RING_DEGREE,
        });
        let mut extra_field_request = valid_request.clone();
        extra_field_request["setupSeed"] = json!("forbidden");
        assert!(compute_setup_commitment_from_opening_request(&extra_field_request).is_err());

        let mut wrong_prime_request = valid_request;
        wrong_prime_request["sourceMessageModulus"] = json!(DATA_PRIMES[1]);
        assert!(compute_setup_commitment_from_opening_request(&wrong_prime_request).is_err());
    }

    #[test]
    fn signed_lifted_commitment_opening_accepts_centered_messages() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('d');
        let signed_message = vec![-21, -13, -8, -5, 0, 5, 8, 13];
        let randomness = shifted_randomness_columns();
        let commitment = compute_setup_signed_lifted_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
            4,
            &signed_message,
            &randomness,
            TEST_RING_DEGREE,
        )?;

        let verification = verify_setup_signed_lifted_commitment_opening(
            &public_matrix_seed_hash,
            &commitment,
            &signed_message,
            &randomness,
            1,
        )?;

        assert_eq!(verification.message_coefficient_bound, 21);
        assert_eq!(
            verification.commitment_root,
            setup_commitment_root(&commitment)?
        );
        let unsigned_message = signed_message
            .iter()
            .map(|coefficient| u128::try_from(*coefficient).unwrap_or(0))
            .collect::<Vec<_>>();
        assert!(
            verify_setup_lifted_commitment_opening(
                &public_matrix_seed_hash,
                &commitment,
                &unsigned_message,
                &randomness,
                1,
            )
            .is_err(),
            "unsigned lifted opening must not reinterpret centered negative responses as zero"
        );

        Ok(())
    }

    #[test]
    fn commitment_homomorphism_preserves_lifted_integer_combination() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('b');
        let first_message = message_coefficients();
        let second_message = vec![u128::from(DATA_PRIMES[0] - 3), 1, 4, 1, 5, 9, 2, 6];
        let first_randomness = randomness_columns(1);
        let second_randomness = shifted_randomness_columns();

        let first_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
            1,
            &first_message,
            &first_randomness,
            TEST_RING_DEGREE,
        )?;
        let second_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
            1,
            &second_message,
            &second_randomness,
            TEST_RING_DEGREE,
        )?;

        let combined_message = first_message
            .iter()
            .zip(second_message.iter())
            .map(|(first_value, second_value)| (3 * first_value) + (5 * second_value))
            .collect::<Vec<_>>();
        let combined_randomness = first_randomness
            .iter()
            .zip(second_randomness.iter())
            .map(|(first_column, second_column)| {
                first_column
                    .iter()
                    .zip(second_column.iter())
                    .map(|(first_value, second_value)| (3 * first_value) + (5 * second_value))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let direct_combined_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
            1,
            &combined_message,
            &combined_randomness,
            TEST_RING_DEGREE,
        )?;
        let homomorphic_combination =
            combine_commitments_for_test(&first_commitment, &second_commitment, 3, 5);

        assert_eq!(homomorphic_combination, direct_combined_commitment);
        assert!(
            combined_message
                .iter()
                .all(|coefficient| setup_coefficient_fits_commitment_modulus_product(*coefficient))
        );
        assert!(
            combined_message
                .iter()
                .any(|coefficient| *coefficient >= u128::from(DATA_PRIMES[0]))
        );
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &direct_combined_commitment,
                &combined_message,
                &combined_randomness,
                8,
            )
            .is_err(),
            "combined lifted openings are outside the source q_l coefficient range and require the VSS carry relation"
        );

        Ok(())
    }

    fn message_coefficients() -> Vec<u128> {
        vec![0, 1, 2, 3, 5, 8, 13, 34]
    }

    fn randomness_columns(bound: i128) -> Vec<Vec<i128>> {
        (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .map(|column_index| {
                (0..TEST_RING_DEGREE)
                    .map(|coefficient_index| {
                        ((column_index + coefficient_index) as i128 % ((2 * bound) + 1)) - bound
                    })
                    .collect()
            })
            .collect()
    }

    fn shifted_randomness_columns() -> Vec<Vec<i128>> {
        (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .map(|column_index| {
                (0..TEST_RING_DEGREE)
                    .map(
                        |coefficient_index| match (column_index + (2 * coefficient_index)) % 3 {
                            0 => -1,
                            1 => 0,
                            _ => 1,
                        },
                    )
                    .collect()
            })
            .collect()
    }

    fn combine_commitments_for_test(
        first_commitment: &super::SetupCommitmentValue,
        second_commitment: &super::SetupCommitmentValue,
        first_scalar: u64,
        second_scalar: u64,
    ) -> super::SetupCommitmentValue {
        let mut combined = first_commitment.clone();
        for ((combined_limb, first_limb), second_limb) in combined
            .limbs
            .iter_mut()
            .zip(first_commitment.limbs.iter())
            .zip(second_commitment.limbs.iter())
        {
            for ((combined_row, first_row), second_row) in combined_limb
                .rows
                .iter_mut()
                .zip(first_limb.rows.iter())
                .zip(second_limb.rows.iter())
            {
                for ((combined_value, first_value), second_value) in combined_row
                    .iter_mut()
                    .zip(first_row.iter())
                    .zip(second_row.iter())
                {
                    let modulus = combined_limb.modulus;
                    *combined_value = add_mod_fast(
                        mul_mod_fast(*first_value, first_scalar % modulus, modulus),
                        mul_mod_fast(*second_value, second_scalar % modulus, modulus),
                        modulus,
                    );
                }
            }
        }

        combined
    }

    fn valid_hash(fill: char) -> String {
        fill.to_string().repeat(128)
    }
}
