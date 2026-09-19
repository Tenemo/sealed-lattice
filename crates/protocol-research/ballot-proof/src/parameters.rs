pub const SYSTEMATIC: usize = 65536;
pub const DOMAIN: usize = 4 * SYSTEMATIC;
pub const QUERY_COUNT: usize = 704;
pub const MASKS: usize = 2 * QUERY_COUNT + 1;
pub const WORDS: usize = 27;
pub const BOOLEANS: usize = 5;
pub const COLUMNS: usize = WORDS + BOOLEANS;
pub const LOOKUPS: usize = WORDS + 5;
pub const ZERO_PRODUCTS: usize = 3;
pub const SUPPORT_PAIRS: usize = 2;
pub const MAX_DEGREE: usize = 2 * SYSTEMATIC - 1;
pub const WITNESS_DEGREE: usize = SYSTEMATIC + MASKS - 1;
pub const SUM_DEGREE: usize = 2 * SYSTEMATIC + MASKS - 2;
pub const ORACLES: usize = COLUMNS + LOOKUPS + 4 + BOOLEANS + ZERO_PRODUCTS + LOOKUPS + 2;
pub const MESSAGE_BYTES: usize = 262144;
pub const FIRST_WIDTH: usize = (COLUMNS + 1) * 16 + 48;
pub const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub const RELATION_TAG: &[u8] = b"linked-scored-ballot/1";
pub const WITNESS_MAGIC: &[u8; 4] = b"LBW1";
pub const HEADER_BYTES: usize = 4 + 64 + 64 + 2 + 1 + 1;
pub const STATEMENT_PARTS: usize = 1;
pub const STATEMENT_BYTES: usize = HEADER_BYTES + 4 * SYSTEMATIC * 109 + 4 * 4096 * 6;
pub fn support(pair: usize) -> (usize, u64) {
    [(1, 512), (16, 128)][pair]
}
pub fn zero_product_columns(index: usize) -> (usize, usize) {
    [(27, 28), (29, 30), (20, 31)][index]
}
pub fn lookup(index: usize) -> (usize, u128) {
    if index < WORDS {
        return (index, 1);
    }
    [(9, 512), (19, 512), (24, 512), (26, 512), (22, 7281)][index - WORDS]
}
pub fn relation_parameters() -> Vec<usize> {
    vec![
        SYSTEMATIC,
        QUERY_COUNT,
        MASKS,
        DOMAIN,
        MAX_DEGREE,
        2,
        MESSAGE_BYTES,
        WORDS,
        BOOLEANS,
        LOOKUPS,
        1024,
        256,
        32768,
        65536,
        27,
        28,
        29,
        30,
        20,
        31,
    ]
}
pub fn degrees() -> Vec<usize> {
    let mut degrees = vec![WITNESS_DEGREE; COLUMNS + LOOKUPS + 3];
    degrees.push(SUM_DEGREE - SYSTEMATIC);
    degrees.extend(vec![
        2 * WITNESS_DEGREE - SYSTEMATIC;
        BOOLEANS + ZERO_PRODUCTS + LOOKUPS
    ]);
    degrees.extend([WITNESS_DEGREE - 1, SYSTEMATIC - 2]);
    assert_eq!(degrees.len(), ORACLES);
    degrees
}
