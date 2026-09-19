pub const SYSTEMATIC: usize = 65536;
pub const DOMAIN: usize = 4 * SYSTEMATIC;
pub const QUERY_COUNT: usize = 704;
pub const MASKS: usize = 2 * QUERY_COUNT + 1;
pub const WORDS: usize = 3;
pub const BOOLEANS: usize = 2;
pub const COLUMNS: usize = WORDS + BOOLEANS;
pub const LOOKUPS: usize = 4;
pub const ZERO_PRODUCTS: usize = 1;
pub const MAX_DEGREE: usize = 2 * SYSTEMATIC - 1;
pub const WITNESS_DEGREE: usize = SYSTEMATIC + MASKS - 1;
pub const SUM_DEGREE: usize = 2 * SYSTEMATIC + MASKS - 2;
pub const ORACLES: usize = COLUMNS + LOOKUPS + 4 + BOOLEANS + ZERO_PRODUCTS + LOOKUPS + 2;
pub const MESSAGE_BYTES: usize = 262144;
pub const FIRST_WIDTH: usize = (COLUMNS + 1) * 16 + 48;
pub const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub const RELATION_TAG: &[u8] = b"recipient-registration-key/1";
pub const WITNESS_MAGIC: &[u8; 4] = b"RKW1";
pub const STATEMENT_PARTS: usize = 3;
pub const STATEMENT_BYTES: usize = 28 + 2 * SYSTEMATIC * 21;
pub fn support(pair: usize) -> (usize, u64) {
    assert_eq!(pair, 0);
    (1, 128)
}

pub fn zero_product_columns(index: usize) -> (usize, usize) {
    assert!(index < ZERO_PRODUCTS);
    (WORDS + 2 * index, WORDS + 2 * index + 1)
}
pub const SUPPORT_PAIRS: usize = ZERO_PRODUCTS;
pub fn lookup(index: usize) -> (usize, u128) {
    assert!(index < LOOKUPS);
    if index < WORDS { (index, 1) } else { (2, 512) }
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
        SYSTEMATIC,
        WORDS,
        BOOLEANS,
        LOOKUPS,
        256,
        96,
        16,
        7,
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
