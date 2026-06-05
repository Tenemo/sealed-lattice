use super::*;

fn chunk_leaf(index: u64, chunk: &[u8]) -> [u8; 64] {
    let mut index_bytes = Vec::new();
    append_varuint(&mut index_bytes, index);

    hash512("transcript-core/chunk-leaf", &[&index_bytes, chunk])
}

fn chunk_node(left: &[u8], right: &[u8]) -> [u8; 64] {
    hash512("transcript-core/chunk-node", &[left, right])
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
        leaves.push(hash512("transcript-core/chunk-empty", &[]));
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
