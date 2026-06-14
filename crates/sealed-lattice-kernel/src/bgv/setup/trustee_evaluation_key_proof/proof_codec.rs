use super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement};
use super::low_degree_proof::{LowDegreePairOpening, LowDegreeProof, LowDegreeQueryOpening};
use super::merkle_commitment::LEAF_SALT_BYTES;
use super::prover::{LimbProof, PhaseQueryOpening, SuccinctEvaluationKeyProof};
use super::relation::{LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, TrusteeEvaluationKeyStatement};
use super::*;

// Canonical binary proof encoding. The decoder is statement-driven: every
// count and width is derived from the statement and the fixed parameters, so
// the byte stream carries no self-describing lengths except folded-layer
// opening lengths that are checked against the statement, and trailing bytes
// are refused.
const PROOF_MAGIC: &[u8; 8] = b"SLTEKP02";

// Every limb modulus the proof commits over is a profile data prime: a ~2^47
// value whose residues fit in six little-endian bytes. Field and challenge-
// extension coordinates are written at exactly that width instead of a full
// eight-byte u64, dropping the two high zero bytes every residue would otherwise
// carry. The width is derived from the basis, so it stays correct if the primes
// change and the const evaluation fails the build if a prime ever no longer
// fits. Length prefixes and Merkle digests keep their natural widths.
const fn field_residue_byte_width() -> usize {
    let mut max_modulus = crate::bgv::profile::DATA_PRIMES[0];
    let mut index = 1;
    while index < crate::bgv::profile::DATA_PRIMES.len() {
        if crate::bgv::profile::DATA_PRIMES[index] > max_modulus {
            max_modulus = crate::bgv::profile::DATA_PRIMES[index];
        }
        index += 1;
    }
    let residue_bits = u64::BITS - (max_modulus - 1).leading_zeros();
    ((residue_bits + 7) / 8) as usize
}
pub(super) const FIELD_RESIDUE_BYTE_WIDTH: usize = field_residue_byte_width();

pub(crate) fn encode_trustee_evaluation_key_proof(proof: &SuccinctEvaluationKeyProof) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PROOF_MAGIC);
    bytes.extend_from_slice(&(proof.limb_proofs.len() as u64).to_le_bytes());
    for limb_proof in &proof.limb_proofs {
        bytes.extend_from_slice(&limb_proof.witness_tree_root);
        bytes.extend_from_slice(&limb_proof.quotient_tree_root);
        write_field_residue_slice(&mut bytes, &limb_proof.masked_consistency_claims);
        for evaluations in &limb_proof.deep_evaluations {
            write_extension_slice(&mut bytes, evaluations);
        }
        encode_low_degree_proof(&mut bytes, &limb_proof.low_degree);
        for opening in &limb_proof.query_openings {
            for slot in 0..2 {
                write_field_residue_slice(&mut bytes, &opening.phase_one_rows[slot]);
                bytes.extend_from_slice(&opening.phase_one_salts[slot]);
                write_hash_slice(&mut bytes, &opening.phase_one_paths[slot]);
                write_field_residue_slice(&mut bytes, &opening.phase_two_rows[slot]);
                bytes.extend_from_slice(&opening.phase_two_salts[slot]);
                write_hash_slice(&mut bytes, &opening.phase_two_paths[slot]);
            }
        }
    }

    bytes
}

pub(crate) fn decode_trustee_evaluation_key_proof(
    statement: &TrusteeEvaluationKeyStatement,
    bytes: &[u8],
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
    statement.validate_shape()?;
    let mut cursor = 0_usize;
    let magic = read_array::<8>(bytes, &mut cursor)?;
    if &magic != PROOF_MAGIC {
        return Err(invalid_succinct_setup_proof(
            "trustee evaluation-key proof has the wrong format marker",
        ));
    }
    let limb_count = usize::try_from(read_u64(bytes, &mut cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("trustee evaluation-key proof limb count does not fit usize")
    })?;
    if limb_count != statement.limb_count() {
        return Err(invalid_succinct_setup_proof(
            "trustee evaluation-key proof limb count does not match the statement",
        ));
    }
    let mut limb_proofs = Vec::with_capacity(limb_count);
    for limb_index in 0..limb_count {
        let layout = LimbColumnLayout::new(statement, limb_index)?;
        let trace_size = layout.trace_size;
        let extension_size = trace_size * DOMAIN_BLOWUP;
        let total_columns = layout.phase_one_physical_count() + PHASE_TWO_COLUMN_COUNT;
        let tree_depth = extension_size.trailing_zeros() as usize;
        let witness_tree_root = read_array::<64>(bytes, &mut cursor)?;
        let quotient_tree_root = read_array::<64>(bytes, &mut cursor)?;
        let modulus = statement.limb_moduli()[limb_index];
        let masked_consistency_claims =
            read_base_field_vec(bytes, &mut cursor, layout.claim_count(), modulus)?;
        let mut deep_evaluations = Vec::with_capacity(DEEP_POINT_COUNT);
        for _ in 0..DEEP_POINT_COUNT {
            deep_evaluations.push(read_extension_vec(
                bytes,
                &mut cursor,
                total_columns,
                modulus,
            )?);
        }
        let low_degree = decode_low_degree_proof(bytes, &mut cursor, extension_size, modulus)?;
        let mut query_openings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
        for _ in 0..LOW_DEGREE_QUERY_COUNT {
            let mut phase_one_rows = [Vec::new(), Vec::new()];
            let mut phase_one_salts = [Vec::new(), Vec::new()];
            let mut phase_one_paths = [Vec::new(), Vec::new()];
            let mut phase_two_rows = [Vec::new(), Vec::new()];
            let mut phase_two_salts = [Vec::new(), Vec::new()];
            let mut phase_two_paths = [Vec::new(), Vec::new()];
            for slot in 0..2 {
                phase_one_rows[slot] = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    layout.phase_one_physical_count(),
                    modulus,
                )?;
                phase_one_salts[slot] = read_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
                phase_one_paths[slot] = read_hash_vec(bytes, &mut cursor, tree_depth)?;
                phase_two_rows[slot] = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    PHASE_TWO_COLUMN_COUNT * CHALLENGE_EXTENSION_DEGREE,
                    modulus,
                )?;
                phase_two_salts[slot] = read_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
                phase_two_paths[slot] = read_hash_vec(bytes, &mut cursor, tree_depth)?;
            }
            query_openings.push(PhaseQueryOpening {
                phase_one_rows,
                phase_one_salts,
                phase_one_paths,
                phase_two_rows,
                phase_two_salts,
                phase_two_paths,
            });
        }
        limb_proofs.push(LimbProof {
            witness_tree_root,
            quotient_tree_root,
            masked_consistency_claims,
            deep_evaluations,
            low_degree,
            query_openings,
        });
    }
    if cursor != bytes.len() {
        return Err(invalid_succinct_setup_proof(
            "trustee evaluation-key proof has trailing bytes",
        ));
    }

    Ok(SuccinctEvaluationKeyProof { limb_proofs })
}

fn encode_low_degree_proof(bytes: &mut Vec<u8>, low_degree: &LowDegreeProof) {
    bytes.extend_from_slice(&(low_degree.folded_layer_roots.len() as u64).to_le_bytes());
    write_hash_slice(bytes, &low_degree.folded_layer_roots);
    write_extension_slice(bytes, &low_degree.final_coefficients);
    for query_opening in &low_degree.query_openings {
        for pair_opening in &query_opening.folded_layer_pairs {
            write_extension_slice(bytes, &pair_opening.pair);
            bytes.extend_from_slice(&(pair_opening.path.len() as u64).to_le_bytes());
            write_hash_slice(bytes, &pair_opening.path);
        }
    }
}

fn decode_low_degree_proof(
    bytes: &[u8],
    cursor: &mut usize,
    initial_domain_size: usize,
    modulus: u64,
) -> CanonicalResult<LowDegreeProof> {
    let fold_count = usize::try_from(read_u64(bytes, cursor)?)
        .map_err(|_| invalid_succinct_setup_proof("low-degree fold count does not fit usize"))?;
    let expected_fold_count = expected_low_degree_committed_fold_count(initial_domain_size)?;
    if fold_count != expected_fold_count {
        return Err(invalid_succinct_setup_proof(
            "low-degree committed fold count does not match the statement",
        ));
    }
    let folded_layer_roots = read_hash_vec(bytes, cursor, fold_count)?;
    let final_coefficients =
        read_extension_vec(bytes, cursor, LOW_DEGREE_FINAL_COEFFICIENT_COUNT, modulus)?;
    let mut query_openings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
    for _ in 0..LOW_DEGREE_QUERY_COUNT {
        let mut folded_layer_pairs = Vec::with_capacity(fold_count);
        for fold_index in 0..fold_count {
            let first = read_extension_element(bytes, cursor, modulus)?;
            let second = read_extension_element(bytes, cursor, modulus)?;
            let path_length = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
                invalid_succinct_setup_proof("low-degree path length does not fit usize")
            })?;
            let expected_path_length =
                expected_low_degree_folded_layer_path_length(initial_domain_size, fold_index)?;
            if path_length != expected_path_length {
                return Err(invalid_succinct_setup_proof(
                    "low-degree folded layer path length does not match the statement",
                ));
            }
            let path = read_hash_vec(bytes, cursor, path_length)?;
            folded_layer_pairs.push(LowDegreePairOpening {
                pair: [first, second],
                path,
            });
        }
        query_openings.push(LowDegreeQueryOpening { folded_layer_pairs });
    }

    Ok(LowDegreeProof {
        folded_layer_roots,
        final_coefficients,
        query_openings,
    })
}

fn expected_low_degree_committed_fold_count(initial_domain_size: usize) -> CanonicalResult<usize> {
    let initial_degree_bound_numerator = initial_domain_size
        .checked_mul(COMMITMENT_BOUND_FACTOR)
        .ok_or_else(|| {
        invalid_succinct_setup_proof("low-degree statement domain size overflowed")
    })?;
    if initial_domain_size == 0
        || !initial_domain_size.is_power_of_two()
        || initial_degree_bound_numerator % DOMAIN_BLOWUP != 0
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement domain does not match the fixed proof parameters",
        ));
    }

    let initial_degree_bound = initial_degree_bound_numerator / DOMAIN_BLOWUP;
    if initial_degree_bound <= LOW_DEGREE_FINAL_COEFFICIENT_COUNT
        || !initial_degree_bound.is_multiple_of(LOW_DEGREE_FINAL_COEFFICIENT_COUNT)
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound does not reach the final coefficient layer",
        ));
    }

    let fold_ratio = initial_degree_bound / LOW_DEGREE_FINAL_COEFFICIENT_COUNT;
    if !fold_ratio.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound does not have a canonical fold depth",
        ));
    }

    Ok(fold_ratio.trailing_zeros() as usize - 1)
}

fn expected_low_degree_folded_layer_path_length(
    initial_domain_size: usize,
    committed_fold_index: usize,
) -> CanonicalResult<usize> {
    let leaf_count_shift = committed_fold_index
        .checked_add(2)
        .ok_or_else(|| invalid_succinct_setup_proof("low-degree folded layer index overflowed"))?;
    if leaf_count_shift >= usize::BITS as usize {
        return Err(invalid_succinct_setup_proof(
            "low-degree folded layer index exceeds the statement domain",
        ));
    }
    let leaf_count = initial_domain_size >> leaf_count_shift;
    if leaf_count == 0 || !leaf_count.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree folded layer tree does not match the statement domain",
        ));
    }

    Ok(leaf_count.trailing_zeros() as usize)
}

fn write_field_residue_slice(bytes: &mut Vec<u8>, values: &[u64]) {
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes()[..FIELD_RESIDUE_BYTE_WIDTH]);
    }
}

fn write_extension_slice(bytes: &mut Vec<u8>, values: &[ChallengeExtensionElement]) {
    for value in values {
        write_field_residue_slice(bytes, value);
    }
}

fn write_hash_slice(bytes: &mut Vec<u8>, hashes: &[[u8; 64]]) {
    for hash in hashes {
        bytes.extend_from_slice(hash);
    }
}

fn read_array<const BYTES: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<[u8; BYTES]> {
    let end = cursor.checked_add(BYTES).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof cursor overflowed")
    })?;
    let slice = bytes.get(*cursor..end).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof ended unexpectedly")
    })?;
    *cursor = end;
    let mut array = [0_u8; BYTES];
    array.copy_from_slice(slice);

    Ok(array)
}

fn read_bytes(bytes: &[u8], cursor: &mut usize, count: usize) -> CanonicalResult<Vec<u8>> {
    let end = cursor.checked_add(count).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof cursor overflowed")
    })?;
    let slice = bytes.get(*cursor..end).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof ended unexpectedly")
    })?;
    *cursor = end;

    Ok(slice.to_vec())
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> CanonicalResult<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_field_residue(bytes: &[u8], cursor: &mut usize, modulus: u64) -> CanonicalResult<u64> {
    let residue = read_array::<FIELD_RESIDUE_BYTE_WIDTH>(bytes, cursor)?;
    let mut buffer = [0_u8; 8];
    buffer[..FIELD_RESIDUE_BYTE_WIDTH].copy_from_slice(&residue);
    let value = u64::from_le_bytes(buffer);
    if value >= modulus {
        return Err(invalid_succinct_setup_proof(
            "trustee evaluation-key proof contains a noncanonical field residue",
        ));
    }

    Ok(value)
}

fn read_base_field_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    (0..count)
        .map(|_| read_field_residue(bytes, cursor, modulus))
        .collect()
}

fn read_extension_element(
    bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<ChallengeExtensionElement> {
    let mut element = [0_u64; CHALLENGE_EXTENSION_DEGREE];
    for coordinate in element.iter_mut() {
        *coordinate = read_field_residue(bytes, cursor, modulus)?;
    }

    Ok(element)
}

fn read_extension_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    (0..count)
        .map(|_| read_extension_element(bytes, cursor, modulus))
        .collect()
}

fn read_hash_vec(bytes: &[u8], cursor: &mut usize, count: usize) -> CanonicalResult<Vec<[u8; 64]>> {
    (0..count)
        .map(|_| read_array::<64>(bytes, cursor))
        .collect()
}
