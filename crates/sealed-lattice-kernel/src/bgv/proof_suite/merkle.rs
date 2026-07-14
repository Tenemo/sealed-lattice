use crate::hashing::hash_framed_parts_512 as hash512;

const MERKLE_LEAF_DOMAIN: &str = "sealed-lattice/proof/merkle/leaf/v1";
const MERKLE_NODE_DOMAIN: &str = "sealed-lattice/proof/merkle/node/v1";

pub(crate) fn leaf_hash(
    application_statement_schema_identifier: u16,
    tree_ordinal: u16,
    leaf_index: usize,
    canonical_leaf_row: &[u8],
) -> [u8; 64] {
    hash512(
        MERKLE_LEAF_DOMAIN,
        &[
            &application_statement_schema_identifier.to_le_bytes(),
            &tree_ordinal.to_le_bytes(),
            &u64::try_from(leaf_index)
                .expect("a usize leaf index fits the canonical u64 field")
                .to_le_bytes(),
            canonical_leaf_row,
        ],
    )
}

pub(crate) fn node_hash(
    application_statement_schema_identifier: u16,
    tree_ordinal: u16,
    level_ordinal: u32,
    node_index: usize,
    left: [u8; 64],
    right: [u8; 64],
) -> [u8; 64] {
    hash512(
        MERKLE_NODE_DOMAIN,
        &[
            &application_statement_schema_identifier.to_le_bytes(),
            &tree_ordinal.to_le_bytes(),
            &level_ordinal.to_le_bytes(),
            &u64::try_from(node_index)
                .expect("a usize node index fits the canonical u64 field")
                .to_le_bytes(),
            &left,
            &right,
        ],
    )
}
