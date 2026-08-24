use std::{
    collections::HashMap,
    mem::size_of,
    sync::{Mutex, OnceLock},
};

use crate::foundation::{CanonicalItem, CanonicalTuple};

use super::commitment_parameters::*;
use super::validation::*;
use super::*;
use crate::bgv::setup::sampling::sample_public_setup_residues;

static SETUP_COMMITMENT_MATRIX_NTT_CACHE: OnceLock<Mutex<SetupCommitmentMatrixNttCache>> =
    OnceLock::new();

/// Coefficient payload retained when every sampled matrix coordinate for the
/// selected commitment primes is resident in the process cache. Structural
/// zero and identity coordinates never enter the cache and are excluded by
/// the same predicate used by commitment computation.
pub(in crate::bgv) fn setup_commitment_matrix_ntt_cache_coefficient_payload_byte_length(
    ring_degree: usize,
) -> CanonicalResult<u64> {
    validate_ring_degree(ring_degree)?;
    let sampled_coordinate_count_per_modulus = (0..SETUP_COMMITMENT_ROW_COUNT)
        .flat_map(|matrix_row_index| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(move |randomness_column_index| (matrix_row_index, randomness_column_index))
        })
        .filter(|(matrix_row_index, randomness_column_index)| {
            structural_matrix_polynomial_kind(*matrix_row_index, *randomness_column_index).is_none()
        })
        .count();
    u64::try_from(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
        .ok()
        .and_then(|modulus_count| {
            u64::try_from(sampled_coordinate_count_per_modulus)
                .ok()
                .and_then(|coordinate_count| modulus_count.checked_mul(coordinate_count))
        })
        .and_then(|coordinate_count| {
            u64::try_from(ring_degree)
                .ok()
                .and_then(|degree| coordinate_count.checked_mul(degree))
        })
        .and_then(|coefficient_count| {
            u64::try_from(size_of::<u64>())
                .ok()
                .and_then(|byte_length| coefficient_count.checked_mul(byte_length))
        })
        .ok_or_else(|| invalid_commitment_input("setup commitment matrix cache size overflowed"))
}

// Version three binds the prime-local rank-one layout. Purpose eleven supplies
// two ternary columns and purpose twelve supplies one independently sampled
// ternary column. A matrix belongs to a commitment prime, not to a sharing
// limb or source trustee.
const SETUP_COMMITMENT_MATRIX_COEFFICIENT_DOMAIN: &str =
    "sealed-lattice-bdlop-commitment/purpose-11-12-matrix-coefficient/v3";
const PUBLIC_SETUP_SAMPLER_CUSTOMIZATION_SCHEMA_IDENTIFIER: u16 = 0x1208;
const SETUP_COMMITMENT_MATRIX_COORDINATE_SCHEMA_IDENTIFIER: u16 = 0x2123;
const SETUP_COMMITMENT_MATRIX_COORDINATE_SCHEMA_VERSION: u16 = 3;
const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const SETUP_COMMITMENT_MATRIX_PART_A1: u16 = 1;
const SETUP_COMMITMENT_MATRIX_PART_A2: u16 = 2;

#[derive(Debug, Default)]
struct SetupCommitmentMatrixNttCache {
    public_matrix_seed_hash: Option<String>,
    entries: HashMap<SetupCommitmentMatrixNttKey, Vec<u64>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SetupCommitmentMatrixNttKey {
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
}

pub(in crate::bgv) fn setup_commitment_matrix_polynomial(
    public_matrix_seed_hash: &str,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    validate_ring_degree(ring_degree)?;
    validate_matrix_coordinate(
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
    )?;
    if modulus != DATA_PRIMES[commitment_modulus_index] {
        return Err(invalid_commitment_input(
            "commitment matrix modulus does not match its selected data-prime coordinate",
        ));
    }

    if let Some(structural_polynomial) =
        structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index)
    {
        let mut coefficients = vec![0_u64; ring_degree];
        if structural_polynomial == StructuralMatrixPolynomial::One {
            coefficients[0] = 1;
        }
        return Ok(coefficients);
    }

    let canonical_customization_bytes = setup_commitment_matrix_sampler_customization(
        commitment_modulus_index,
        matrix_row_index,
        randomness_column_index,
    )?;
    sample_public_setup_residues(
        public_matrix_seed_hash,
        &canonical_customization_bytes,
        modulus,
        ring_degree,
    )
}

pub(super) fn setup_commitment_matrix_ntt(
    public_matrix_seed_hash: &str,
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let key = SetupCommitmentMatrixNttKey {
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

fn setup_commitment_matrix_sampler_customization(
    commitment_modulus_index: usize,
    matrix_row_index: usize,
    randomness_column_index: usize,
) -> CanonicalResult<Vec<u8>> {
    let commitment_data_prime_index = u16::try_from(commitment_modulus_index)
        .map_err(|_| invalid_commitment_input("commitment data-prime index does not fit u16"))?;
    let (matrix_part, row, column) = if matrix_row_index < SETUP_COMMITMENT_MODULE_RANK {
        (
            SETUP_COMMITMENT_MATRIX_PART_A1,
            matrix_row_index,
            randomness_column_index,
        )
    } else {
        (SETUP_COMMITMENT_MATRIX_PART_A2, 0, randomness_column_index)
    };
    let row = u16::try_from(row)
        .map_err(|_| invalid_commitment_input("commitment matrix row does not fit u16"))?;
    let column = u16::try_from(column)
        .map_err(|_| invalid_commitment_input("commitment matrix column does not fit u16"))?;
    let canonical_coordinate_bytes = CanonicalTuple::new(
        SETUP_COMMITMENT_MATRIX_COORDINATE_SCHEMA_IDENTIFIER,
        SETUP_COMMITMENT_MATRIX_COORDINATE_SCHEMA_VERSION,
        vec![
            CanonicalItem::unsigned16(commitment_data_prime_index),
            CanonicalItem::unsigned16(matrix_part),
            CanonicalItem::unsigned16(row),
            CanonicalItem::unsigned16(column),
        ],
    )
    .encode()
    .map_err(|error| {
        invalid_commitment_input(format!(
            "commitment matrix coordinate encoding failed: {error}"
        ))
    })?;

    CanonicalTuple::new(
        PUBLIC_SETUP_SAMPLER_CUSTOMIZATION_SCHEMA_IDENTIFIER,
        FOUNDATION_SCHEMA_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(SETUP_COMMITMENT_MATRIX_COEFFICIENT_DOMAIN).map_err(
                |error| {
                    invalid_commitment_input(format!(
                        "commitment matrix role-domain encoding failed: {error}"
                    ))
                },
            )?,
            CanonicalItem::variable_bytes(canonical_coordinate_bytes).map_err(|error| {
                invalid_commitment_input(format!(
                    "commitment matrix coordinate byte encoding failed: {error}"
                ))
            })?,
        ],
    )
    .encode()
    .map_err(|error| {
        invalid_commitment_input(format!(
            "commitment matrix sampler customization encoding failed: {error}"
        ))
    })
}

pub(in super::super) fn structural_matrix_polynomial_kind(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_core::encode_hex;

    #[test]
    fn selected_matrix_cache_accounting_matches_the_live_sampled_coordinates() -> CanonicalResult<()>
    {
        assert_eq!(
            setup_commitment_matrix_ntt_cache_coefficient_payload_byte_length(POLYNOMIAL_DEGREE,)?,
            2_359_296
        );
        Ok(())
    }

    #[test]
    fn matrix_sampler_customization_has_the_exact_version_three_encoding() -> CanonicalResult<()> {
        let customization = setup_commitment_matrix_sampler_customization(0, 0, 0)?;

        assert_eq!(
            encode_hex(&customization),
            concat!(
                "0812010002000000020047000000430000007365616c65642d6c6174746963652d",
                "62646c6f702d636f6d6d69746d656e742f707572706f73652d31312d31322d6d",
                "61747269782d636f656666696369656e742f763301002c00000028000000232103",
                "000400000003000200000000000300020000000100030002000000000003000200",
                "00000000"
            )
        );
        Ok(())
    }

    #[test]
    fn matrix_sampler_matches_the_independent_cshake_vector() -> CanonicalResult<()> {
        let zero_seed = "00".repeat(64);
        let a1 = setup_commitment_matrix_polynomial(&zero_seed, 0, 0, 0, 8, DATA_PRIMES[0])?;
        let a2 = setup_commitment_matrix_polynomial(
            &zero_seed,
            0,
            SETUP_COMMITMENT_MODULE_RANK,
            0,
            8,
            DATA_PRIMES[0],
        )?;

        assert_eq!(
            a1,
            vec![
                1_180_583_222,
                683_066_235,
                1_429_182_874,
                1_318_510_005,
                1_038_040_795,
                1_464_599_517,
                1_218_598_985,
                1_498_491_642,
            ]
        );
        assert_eq!(
            a2,
            vec![
                1_578_872_374,
                1_659_540_755,
                1_167_329_729,
                1_428_181_724,
                97_765_557,
                1_169_764_680,
                323_352_622,
                1_118_000_110,
            ]
        );
        assert_ne!(a1, a2);
        Ok(())
    }

    #[test]
    fn hnf_structural_polynomials_are_not_sampled() -> CanonicalResult<()> {
        let seed = "11".repeat(64);
        let identity = setup_commitment_matrix_polynomial(
            &seed,
            0,
            0,
            SETUP_COMMITMENT_MODULE_RANK + 1,
            8,
            DATA_PRIMES[0],
        )?;
        let message_blinding = setup_commitment_matrix_polynomial(
            &seed,
            0,
            SETUP_COMMITMENT_MODULE_RANK,
            SETUP_COMMITMENT_MODULE_RANK,
            8,
            DATA_PRIMES[0],
        )?;
        let zero = setup_commitment_matrix_polynomial(
            &seed,
            0,
            SETUP_COMMITMENT_MODULE_RANK,
            SETUP_COMMITMENT_MODULE_RANK + 1,
            8,
            DATA_PRIMES[0],
        )?;

        assert_eq!(identity, vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(message_blinding, identity);
        assert_eq!(zero, vec![0; 8]);
        Ok(())
    }

    #[test]
    fn matrix_sampler_rejects_a_modulus_not_owned_by_the_coordinate() {
        let error =
            setup_commitment_matrix_polynomial(&"22".repeat(64), 0, 0, 0, 8, DATA_PRIMES[1])
                .expect_err("a matrix coordinate cannot select an unrelated modulus");

        assert!(error.message.contains("does not match"));
    }
}
