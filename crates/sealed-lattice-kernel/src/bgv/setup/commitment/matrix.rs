use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use super::profile::*;
use super::validation::*;
use super::*;

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

pub(in super::super) fn setup_commitment_matrix_sampled_entries(
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

pub(in super::super) fn setup_commitment_matrix_polynomial(
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

pub(super) fn setup_commitment_matrix_ntt(
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
pub(in super::super) fn setup_commitment_matrix_coefficients_cached(
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

// Structural identity and message-blinding entries are the ring scalar 1
// (constant coefficient only), not an all-ones coefficient vector.
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
