use super::*;

fn chunk_leaf(index: u64, chunk: &[u8]) -> [u8; 64] {
    let mut index_bytes = Vec::new();
    append_varuint(&mut index_bytes, index);

    hash_framed_parts_512("transcript-core/chunk-leaf", &[&index_bytes, chunk])
}

fn chunk_node(left: &[u8], right: &[u8]) -> [u8; 64] {
    hash_framed_parts_512("transcript-core/chunk-node", &[left, right])
}

pub fn chunk_root(input: &[u8], chunk_size: usize) -> CanonicalResult<String> {
    if chunk_size == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidChunkSize,
            "chunk size must be greater than zero",
        ));
    }

    let mut leaves: Vec<[u8; 64]> = input
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| chunk_leaf(index as u64, chunk))
        .collect();

    if leaves.is_empty() {
        leaves.push(hash_framed_parts_512(
            "transcript-core/chunk-empty",
            &[],
        ));
    }

    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut index = 0;
        while index < leaves.len() {
            let left = leaves[index];
            let right = if index + 1 < leaves.len() {
                leaves[index + 1]
            } else {
                left
            };
            next_level.push(chunk_node(&left, &right));
            index += 2;
        }
        leaves = next_level;
    }

    let mut chunk_size_bytes = Vec::new();
    append_varuint(&mut chunk_size_bytes, chunk_size as u64);
    let mut input_length_bytes = Vec::new();
    append_varuint(&mut input_length_bytes, input.len() as u64);

    Ok(hash512_hex(
        "transcript-core/chunk-root",
        &[&chunk_size_bytes, &input_length_bytes, &leaves[0]],
    ))
}

#[cfg(test)]
mod tests {
    use super::chunk_root;

    // A zero chunk size is rejected rather than used as a divisor.
    #[test]
    fn chunk_root_rejects_zero_chunk_size() {
        assert!(chunk_root(b"abcd", 0).is_err());
    }

    // The root binds the input length and handles a final chunk shorter than the
    // chunk size without panicking; a flipped byte in that final chunk changes
    // the root.
    #[test]
    fn chunk_root_binds_input_length_and_truncated_final_chunk() {
        let five = chunk_root(b"\x01\x02\x03\x04\x05", 2).expect("truncated final chunk");
        let six = chunk_root(b"\x01\x02\x03\x04\x05\x06", 2).expect("even final chunk");
        assert_ne!(five, six);
        let five_flipped =
            chunk_root(b"\x01\x02\x03\x04\x09", 2).expect("flipped final byte roots");
        assert_ne!(five, five_flipped);
    }

    // The odd-leaf pairing step duplicates the final leaf. Physically repeating
    // the final chunk to build one more leaf must not reproduce the same root:
    // both the per-leaf index binding and the input-length binding defend against
    // this duplicate-last-node Merkle restatement (CVE-2012-2459 class).
    #[test]
    fn chunk_root_resists_duplicate_last_leaf_restatement() {
        let three_leaves =
            chunk_root(b"\xaa\xbb\xcc\xdd\xee\xff", 2).expect("three leaves, final duplicated");
        let four_leaves = chunk_root(b"\xaa\xbb\xcc\xdd\xee\xff\xee\xff", 2)
            .expect("four leaves with the final chunk repeated");
        assert_ne!(three_leaves, four_leaves);
    }
}
