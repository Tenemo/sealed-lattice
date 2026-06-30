use super::extension_field::{CHALLENGE_EXTENSION_DEGREE, ChallengeExtensionElement};
use super::low_degree_proof::{LowDegreeProof, LowDegreeQueryOpening, LowDegreeSiblingOpening};
use super::merkle_commitment::{
    BatchedMerkleOpening, LEAF_SALT_BYTES, MERKLE_DIGEST_BYTES, MerkleDigest,
};
use super::prover::{LimbProof, PhaseQueryOpening, SuccinctEvaluationKeyProof};
use super::relation::{LimbColumnLayout, PHASE_TWO_COLUMN_COUNT, TrusteeEvaluationKeyStatement};
use super::*;
use crate::bgv::profile::DATA_PRIMES;

// Canonical binary proof encoding. The decoder is statement-driven: every
// count and width is derived from the statement and the fixed parameters, so
// the byte stream carries no self-describing lengths except compact
// folded-layer sibling tables and folded-layer opening lengths that are checked
// against the statement, and trailing bytes are refused.
const PROOF_MAGIC: &[u8; 8] = b"BGVPRF19";

// Every limb modulus the proof commits over is a profile data prime: a ~2^47
// value whose residues fit in 47 bits. Field and challenge-extension
// coordinates are bit-packed at exactly that width instead of carrying the high
// padding bit left by a byte-aligned encoding. The width is derived from the
// basis, so it stays correct if the primes change. Length prefixes and Merkle
// digests keep their natural widths.
const fn field_residue_bit_width() -> usize {
    let mut max_modulus = crate::bgv::profile::DATA_PRIMES[0];
    let mut index = 1;
    while index < crate::bgv::profile::DATA_PRIMES.len() {
        if crate::bgv::profile::DATA_PRIMES[index] > max_modulus {
            max_modulus = crate::bgv::profile::DATA_PRIMES[index];
        }
        index += 1;
    }
    let residue_bits = u64::BITS - (max_modulus - 1).leading_zeros();
    residue_bits as usize
}
pub(in crate::bgv::setup) const FIELD_RESIDUE_BIT_WIDTH: usize = field_residue_bit_width();

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
        encode_low_degree_proof(&mut bytes, &limb_proof.sumcheck_residual_low_degree);
        for opening in &limb_proof.query_openings {
            for slot in 0..2 {
                write_field_residue_slice(&mut bytes, &opening.phase_one_rows[slot]);
            }
            bytes.extend_from_slice(&opening.phase_one_pair_salt);
            for slot in 0..2 {
                write_field_residue_slice(&mut bytes, &opening.phase_two_rows[slot]);
            }
            bytes.extend_from_slice(&opening.phase_two_pair_salt);
        }
        write_batched_opening(&mut bytes, &limb_proof.witness_batch_opening);
        write_batched_opening(&mut bytes, &limb_proof.quotient_batch_opening);
    }

    bytes
}

pub(crate) fn decode_trustee_evaluation_key_proof(
    statement: &TrusteeEvaluationKeyStatement,
    bytes: &[u8],
) -> CanonicalResult<SuccinctEvaluationKeyProof> {
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
    let proof_limb_indices = statement.proof_limb_indices();
    if limb_count != proof_limb_indices.len() {
        return Err(invalid_succinct_setup_proof(
            "trustee evaluation-key proof limb count does not match the statement",
        ));
    }
    let mut limb_proofs = Vec::with_capacity(limb_count);
    for limb_index in proof_limb_indices {
        let layout = LimbColumnLayout::new(statement, limb_index)?;
        let trace_size = layout.trace_size;
        let extension_size = trace_size * DOMAIN_BLOWUP;
        let total_columns = layout.phase_one_physical_count() + PHASE_TWO_COLUMN_COUNT;
        let phase_tree_depth = (extension_size / 2).trailing_zeros() as usize;
        let witness_tree_root = read_array::<MERKLE_DIGEST_BYTES>(bytes, &mut cursor)?;
        let quotient_tree_root = read_array::<MERKLE_DIGEST_BYTES>(bytes, &mut cursor)?;
        let modulus = DATA_PRIMES[limb_index];
        let masked_consistency_claims =
            read_base_field_vec(bytes, &mut cursor, layout.claim_count(), modulus)?;
        let mut deep_evaluations = Vec::with_capacity(DEEP_EVALUATION_POINT_COUNT);
        for _ in 0..DEEP_EVALUATION_POINT_COUNT {
            deep_evaluations.push(read_extension_vec(
                bytes,
                &mut cursor,
                total_columns,
                modulus,
            )?);
        }
        let low_degree = decode_low_degree_proof(
            bytes,
            &mut cursor,
            extension_size,
            COMMITMENT_BOUND_FACTOR * trace_size,
            modulus,
        )?;
        let sumcheck_residual_low_degree =
            decode_low_degree_proof(bytes, &mut cursor, extension_size, trace_size, modulus)?;
        let mut query_openings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
        for _ in 0..LOW_DEGREE_QUERY_COUNT {
            let mut phase_one_rows = [Vec::new(), Vec::new()];
            let mut phase_two_rows = [Vec::new(), Vec::new()];
            for phase_one_row in &mut phase_one_rows {
                *phase_one_row = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    layout.phase_one_physical_count(),
                    modulus,
                )?;
            }
            let phase_one_pair_salt = read_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
            for phase_two_row in &mut phase_two_rows {
                *phase_two_row = read_base_field_vec(
                    bytes,
                    &mut cursor,
                    PHASE_TWO_COLUMN_COUNT * CHALLENGE_EXTENSION_DEGREE,
                    modulus,
                )?;
            }
            let phase_two_pair_salt = read_bytes(bytes, &mut cursor, LEAF_SALT_BYTES)?;
            query_openings.push(PhaseQueryOpening {
                phase_one_rows,
                phase_one_pair_salt,
                phase_two_rows,
                phase_two_pair_salt,
            });
        }
        // The witness and phase-two pair trees open at most one leaf per shared
        // low-degree query.
        let witness_batch_node_bound = LOW_DEGREE_QUERY_COUNT * phase_tree_depth;
        let quotient_batch_node_bound = LOW_DEGREE_QUERY_COUNT * phase_tree_depth;
        let witness_batch_opening =
            read_batched_opening(bytes, &mut cursor, witness_batch_node_bound)?;
        let quotient_batch_opening =
            read_batched_opening(bytes, &mut cursor, quotient_batch_node_bound)?;
        limb_proofs.push(LimbProof {
            witness_tree_root,
            quotient_tree_root,
            masked_consistency_claims,
            deep_evaluations,
            low_degree,
            sumcheck_residual_low_degree,
            query_openings,
            witness_batch_opening,
            quotient_batch_opening,
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
    for fold_index in 0..low_degree.folded_layer_roots.len() {
        write_low_degree_sibling_table(bytes, low_degree, fold_index);
    }
    for layer_opening in &low_degree.layer_batch_openings {
        write_batched_opening(bytes, layer_opening);
    }
}

fn write_low_degree_sibling_table(
    bytes: &mut Vec<u8>,
    low_degree: &LowDegreeProof,
    fold_index: usize,
) {
    let mut unique_siblings: Vec<ChallengeExtensionElement> = Vec::new();
    let mut references = Vec::with_capacity(low_degree.query_openings.len());
    let mut raw_siblings = Vec::with_capacity(low_degree.query_openings.len());
    for query_opening in &low_degree.query_openings {
        let sibling = query_opening.folded_layer_siblings[fold_index].sibling;
        raw_siblings.push(sibling);
        let table_index = if let Some(existing_index) =
            unique_siblings.iter().position(|entry| *entry == sibling)
        {
            existing_index
        } else {
            unique_siblings.push(sibling);
            unique_siblings.len() - 1
        };
        references
            .push(u8::try_from(table_index).expect("low-degree sibling table fits in one byte"));
    }
    let compressed_sibling_bytes = low_degree_sibling_table_value_byte_count(unique_siblings.len())
        + low_degree_sibling_reference_byte_count(unique_siblings.len());
    let raw_sibling_bytes = low_degree_sibling_table_value_byte_count(LOW_DEGREE_QUERY_COUNT);
    if unique_siblings.len() < LOW_DEGREE_QUERY_COUNT
        && compressed_sibling_bytes < raw_sibling_bytes
    {
        bytes.extend_from_slice(&(unique_siblings.len() as u64).to_le_bytes());
        write_extension_slice(bytes, &unique_siblings);
        write_low_degree_sibling_references(bytes, &references, unique_siblings.len());
    } else {
        bytes.extend_from_slice(&(LOW_DEGREE_QUERY_COUNT as u64).to_le_bytes());
        write_extension_slice(bytes, &raw_siblings);
    }
}

fn low_degree_sibling_table_value_byte_count(element_count: usize) -> usize {
    field_residue_slice_byte_count(
        element_count
            .checked_mul(CHALLENGE_EXTENSION_DEGREE)
            .expect("low-degree sibling table residue count must fit usize"),
    )
    .expect("low-degree sibling table byte count must fit usize")
}

fn low_degree_sibling_reference_bit_width(table_count: usize) -> usize {
    if table_count <= 1 {
        0
    } else {
        usize::BITS as usize - (table_count - 1).leading_zeros() as usize
    }
}

fn low_degree_sibling_reference_byte_count(table_count: usize) -> usize {
    LOW_DEGREE_QUERY_COUNT
        .checked_mul(low_degree_sibling_reference_bit_width(table_count))
        .expect("low-degree sibling reference bit count must fit usize")
        .div_ceil(8)
}

fn write_low_degree_sibling_references(bytes: &mut Vec<u8>, references: &[u8], table_count: usize) {
    let bit_width = low_degree_sibling_reference_bit_width(table_count);
    let byte_count = low_degree_sibling_reference_byte_count(table_count);
    let start = bytes.len();
    bytes.resize(start + byte_count, 0);
    let mut bit_cursor = 0_usize;
    for reference in references {
        write_fixed_width_bits(
            &mut bytes[start..],
            &mut bit_cursor,
            u64::from(*reference),
            bit_width,
        );
    }
}

fn decode_low_degree_proof(
    bytes: &[u8],
    cursor: &mut usize,
    initial_domain_size: usize,
    initial_degree_bound: usize,
    modulus: u64,
) -> CanonicalResult<LowDegreeProof> {
    let fold_count = usize::try_from(read_u64(bytes, cursor)?)
        .map_err(|_| invalid_succinct_setup_proof("low-degree fold count does not fit usize"))?;
    let expected_fold_count = expected_low_degree_committed_fold_count(initial_degree_bound)?;
    if fold_count != expected_fold_count {
        return Err(invalid_succinct_setup_proof(
            "low-degree committed fold count does not match the statement",
        ));
    }
    let folded_layer_roots = read_hash_vec(bytes, cursor, fold_count)?;
    let final_coefficient_count =
        expected_low_degree_final_coefficient_count(initial_degree_bound)?;
    let final_coefficients = read_extension_vec(bytes, cursor, final_coefficient_count, modulus)?;
    let mut folded_layer_siblings_by_query: Vec<Vec<LowDegreeSiblingOpening>> = (0
        ..LOW_DEGREE_QUERY_COUNT)
        .map(|_| Vec::with_capacity(fold_count))
        .collect();
    for _fold_index in 0..fold_count {
        let siblings = read_low_degree_sibling_table(bytes, cursor, modulus)?;
        for (query_siblings, sibling) in folded_layer_siblings_by_query
            .iter_mut()
            .zip(siblings.into_iter())
        {
            query_siblings.push(LowDegreeSiblingOpening { sibling });
        }
    }
    let query_openings = folded_layer_siblings_by_query
        .into_iter()
        .map(|folded_layer_siblings| LowDegreeQueryOpening {
            folded_layer_siblings,
        })
        .collect();
    let mut layer_batch_openings = Vec::with_capacity(fold_count);
    for fold_index in 0..fold_count {
        // Each query opens one leaf per layer, so the batched node count cannot
        // exceed one path's worth per query at that layer's depth.
        let layer_depth =
            expected_low_degree_folded_layer_path_length(initial_domain_size, fold_index)?;
        let maximum_nodes = LOW_DEGREE_QUERY_COUNT * layer_depth;
        layer_batch_openings.push(read_batched_opening(bytes, cursor, maximum_nodes)?);
    }

    Ok(LowDegreeProof {
        folded_layer_roots,
        final_coefficients,
        query_openings,
        layer_batch_openings,
    })
}

fn read_low_degree_sibling_table(
    bytes: &[u8],
    cursor: &mut usize,
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let table_count = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("low-degree sibling table count does not fit usize")
    })?;
    if table_count == 0 || table_count > LOW_DEGREE_QUERY_COUNT {
        return Err(invalid_succinct_setup_proof(
            "low-degree sibling table count exceeds the statement bound",
        ));
    }
    let table = read_extension_vec(bytes, cursor, table_count, modulus)?;
    if table_count == LOW_DEGREE_QUERY_COUNT {
        let mut unique_siblings: Vec<ChallengeExtensionElement> = Vec::new();
        for sibling in &table {
            if !unique_siblings.contains(sibling) {
                unique_siblings.push(*sibling);
            }
        }
        let compressed_sibling_bytes =
            low_degree_sibling_table_value_byte_count(unique_siblings.len())
                + low_degree_sibling_reference_byte_count(unique_siblings.len());
        let raw_sibling_bytes = low_degree_sibling_table_value_byte_count(LOW_DEGREE_QUERY_COUNT);
        if unique_siblings.len() < LOW_DEGREE_QUERY_COUNT
            && compressed_sibling_bytes < raw_sibling_bytes
        {
            return Err(invalid_succinct_setup_proof(
                "low-degree sibling table is not compact",
            ));
        }

        return Ok(table);
    }

    for earlier_index in 0..table.len() {
        if table[earlier_index + 1..]
            .iter()
            .any(|entry| *entry == table[earlier_index])
        {
            return Err(invalid_succinct_setup_proof(
                "low-degree sibling table contains a duplicate entry",
            ));
        }
    }

    let mut siblings = Vec::with_capacity(LOW_DEGREE_QUERY_COUNT);
    let mut used_table_entries = vec![false; table_count];
    let mut next_first_use_index = 0_usize;
    let bit_width = low_degree_sibling_reference_bit_width(table_count);
    let reference_byte_count = low_degree_sibling_reference_byte_count(table_count);
    let reference_bytes = read_bytes(bytes, cursor, reference_byte_count)?;
    let mut bit_cursor = 0_usize;
    for _query_index in 0..LOW_DEGREE_QUERY_COUNT {
        let reference =
            read_fixed_width_bits(&reference_bytes, &mut bit_cursor, bit_width) as usize;
        if reference >= table_count {
            return Err(invalid_succinct_setup_proof(
                "low-degree sibling table reference exceeds the table",
            ));
        }
        if reference > next_first_use_index {
            return Err(invalid_succinct_setup_proof(
                "low-degree sibling table references are not canonical",
            ));
        }
        if reference == next_first_use_index {
            next_first_use_index += 1;
        }
        used_table_entries[reference] = true;
        siblings.push(table[reference]);
    }
    let used_bits_in_final_byte = bit_cursor % 8;
    if used_bits_in_final_byte != 0 {
        let padding_mask = u8::MAX << used_bits_in_final_byte;
        if reference_bytes[reference_byte_count - 1] & padding_mask != 0 {
            return Err(invalid_succinct_setup_proof(
                "low-degree sibling table contains noncanonical reference padding",
            ));
        }
    }
    if used_table_entries.iter().any(|used| !*used) {
        return Err(invalid_succinct_setup_proof(
            "low-degree sibling table has an unused entry",
        ));
    }

    Ok(siblings)
}

// Committed layer count is total folds minus one: the final fold is transmitted
// as coefficients, not a Merkle-committed layer.
fn expected_low_degree_committed_fold_count(initial_degree_bound: usize) -> CanonicalResult<usize> {
    let final_coefficient_count =
        expected_low_degree_final_coefficient_count(initial_degree_bound)?;
    if !initial_degree_bound.is_power_of_two()
        || !initial_degree_bound.is_multiple_of(final_coefficient_count)
    {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound does not reach the final coefficient layer",
        ));
    }

    let fold_ratio = initial_degree_bound / final_coefficient_count;
    if !fold_ratio.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound does not have a canonical fold depth",
        ));
    }

    Ok(fold_ratio.trailing_zeros() as usize - 1)
}

fn expected_low_degree_final_coefficient_count(
    initial_degree_bound: usize,
) -> CanonicalResult<usize> {
    low_degree_final_coefficient_count(initial_degree_bound)
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

fn field_residue_slice_byte_count(count: usize) -> Option<usize> {
    count
        .checked_mul(FIELD_RESIDUE_BIT_WIDTH)
        .map(|bit_count| bit_count.div_ceil(8))
}

// The bit width is compile-time derived from the data primes; decode-side
// residue and padding checks make the packed encoding canonical for transcript
// binding.
fn write_field_residue_slice(bytes: &mut Vec<u8>, values: &[u64]) {
    let byte_count = field_residue_slice_byte_count(values.len())
        .expect("field residue slice bit count must fit usize");
    let start = bytes.len();
    bytes.resize(start + byte_count, 0);
    let mut bit_cursor = 0_usize;
    for value in values {
        write_fixed_width_bits(
            &mut bytes[start..],
            &mut bit_cursor,
            *value,
            FIELD_RESIDUE_BIT_WIDTH,
        );
    }
}

fn write_fixed_width_bits(bytes: &mut [u8], bit_cursor: &mut usize, value: u64, bit_width: usize) {
    let mut written_bits = 0_usize;
    while written_bits < bit_width {
        let byte_index = *bit_cursor / 8;
        let bit_index = *bit_cursor % 8;
        let available_bits = 8 - bit_index;
        let chunk_bits = (bit_width - written_bits).min(available_bits);
        let chunk_mask = (1_u64 << chunk_bits) - 1;
        let chunk = ((value >> written_bits) & chunk_mask) as u8;
        bytes[byte_index] |= chunk << bit_index;
        *bit_cursor += chunk_bits;
        written_bits += chunk_bits;
    }
}

fn write_extension_slice(bytes: &mut Vec<u8>, values: &[ChallengeExtensionElement]) {
    let residue_count = values
        .len()
        .checked_mul(CHALLENGE_EXTENSION_DEGREE)
        .expect("extension residue count must fit usize");
    let byte_count =
        field_residue_slice_byte_count(residue_count).expect("extension slice must fit usize");
    let start = bytes.len();
    bytes.resize(start + byte_count, 0);
    let mut bit_cursor = 0_usize;
    for value in values {
        for coordinate in value {
            write_fixed_width_bits(
                &mut bytes[start..],
                &mut bit_cursor,
                *coordinate,
                FIELD_RESIDUE_BIT_WIDTH,
            );
        }
    }
}

fn write_hash_slice(bytes: &mut Vec<u8>, hashes: &[MerkleDigest]) {
    for hash in hashes {
        bytes.extend_from_slice(hash);
    }
}

fn write_batched_opening(bytes: &mut Vec<u8>, opening: &BatchedMerkleOpening) {
    bytes.extend_from_slice(&(opening.authentication_nodes.len() as u64).to_le_bytes());
    write_hash_slice(bytes, &opening.authentication_nodes);
}

// The node count is self-describing because it depends on the queried positions,
// which the decoder does not replay. It is bounded against `maximum_nodes` (a
// per-tree upper bound the caller derives from the query count and tree depth)
// so a malformed proof cannot force an oversized allocation; the verifier then
// rejects any count that does not reconstruct the committed root.
fn read_batched_opening(
    bytes: &[u8],
    cursor: &mut usize,
    maximum_nodes: usize,
) -> CanonicalResult<BatchedMerkleOpening> {
    let node_count = usize::try_from(read_u64(bytes, cursor)?).map_err(|_| {
        invalid_succinct_setup_proof("batched opening node count does not fit usize")
    })?;
    if node_count > maximum_nodes {
        return Err(invalid_succinct_setup_proof(
            "batched opening node count exceeds the statement bound",
        ));
    }
    let authentication_nodes = read_hash_vec(bytes, cursor, node_count)?;

    Ok(BatchedMerkleOpening {
        authentication_nodes,
    })
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

fn read_base_field_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let byte_count = field_residue_slice_byte_count(count).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof field residue count overflowed")
    })?;
    let end = cursor.checked_add(byte_count).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof cursor overflowed")
    })?;
    let slice = bytes.get(*cursor..end).ok_or_else(|| {
        invalid_succinct_setup_proof("trustee evaluation-key proof ended unexpectedly")
    })?;
    *cursor = end;
    let mut values = Vec::with_capacity(count);
    let mut bit_cursor = 0_usize;
    for _ in 0..count {
        let value = read_fixed_width_bits(slice, &mut bit_cursor, FIELD_RESIDUE_BIT_WIDTH);
        if value >= modulus {
            return Err(invalid_succinct_setup_proof(
                "trustee evaluation-key proof contains a noncanonical field residue",
            ));
        }
        values.push(value);
    }
    let used_bits_in_final_byte = bit_cursor % 8;
    if used_bits_in_final_byte != 0 {
        let padding_mask = u8::MAX << used_bits_in_final_byte;
        if slice[byte_count - 1] & padding_mask != 0 {
            return Err(invalid_succinct_setup_proof(
                "trustee evaluation-key proof contains noncanonical field-residue padding",
            ));
        }
    }

    Ok(values)
}

fn read_fixed_width_bits(bytes: &[u8], bit_cursor: &mut usize, bit_width: usize) -> u64 {
    let mut value = 0_u64;
    let mut read_bits = 0_usize;
    while read_bits < bit_width {
        let byte = bytes[*bit_cursor / 8];
        let bit_index = *bit_cursor % 8;
        let available_bits = 8 - bit_index;
        let chunk_bits = (bit_width - read_bits).min(available_bits);
        let chunk_mask = ((1_u16 << chunk_bits) - 1) as u8;
        let chunk = ((byte >> bit_index) & chunk_mask) as u64;
        value |= chunk << read_bits;
        *bit_cursor += chunk_bits;
        read_bits += chunk_bits;
    }

    value
}

fn read_extension_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let residue_count = count
        .checked_mul(CHALLENGE_EXTENSION_DEGREE)
        .ok_or_else(|| {
            invalid_succinct_setup_proof("trustee evaluation-key proof extension count overflowed")
        })?;
    let residues = read_base_field_vec(bytes, cursor, residue_count, modulus)?;
    Ok(residues
        .chunks_exact(CHALLENGE_EXTENSION_DEGREE)
        .map(|chunk| chunk.try_into().expect("chunk has extension degree"))
        .collect())
}

fn read_hash_vec(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
) -> CanonicalResult<Vec<MerkleDigest>> {
    (0..count)
        .map(|_| read_array::<MERKLE_DIGEST_BYTES>(bytes, cursor))
        .collect()
}
