pub const SYSTEMATIC: usize = 65_536;
pub const DOMAIN: usize = 4 * SYSTEMATIC;
pub const QUERY_COUNT: usize = 704;
pub const MASKS: usize = 2 * QUERY_COUNT + 1;
pub const WORDS: usize = 333;
pub const BOOLEANS: usize = 32;
pub const COLUMNS: usize = WORDS + BOOLEANS;
pub const LOOKUPS: usize = WORDS + 45;
pub const ZERO_PRODUCTS: usize = 13;
pub const RELATION_TAG: &[u8] = b"complete-setup-words/1";
pub const WITNESS_MAGIC: &[u8; 4] = b"SFW1";
pub const STATEMENT_PARTS: usize = 76;
pub const STATEMENT_BYTES: usize =
    145 + 42 * SYSTEMATIC * 109 + 31 * SYSTEMATIC * 21 + 2 * 4096 * 6;
pub const MAX_DEGREE: usize = 2 * SYSTEMATIC - 1;
pub const WITNESS_DEGREE: usize = SYSTEMATIC + MASKS - 1;
pub const SUM_DEGREE: usize = 2 * SYSTEMATIC + MASKS - 2;
pub const ORACLES: usize = COLUMNS + LOOKUPS + 4 + BOOLEANS + ZERO_PRODUCTS + LOOKUPS + 2;
pub const MESSAGE_BYTES: usize = 262_144;
pub const FIRST_WIDTH: usize = (COLUMNS + 1) * 16 + 48;
pub const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub fn support(pair: usize) -> (usize, u64) {
    assert!(pair < ZERO_PRODUCTS);
    (
        if pair == 12 { SYSTEMATIC / 4096 } else { 1 },
        if pair < 2 { 512 } else { 128 },
    )
}

pub fn zero_product_columns(index: usize) -> (usize, usize) {
    assert!(index < ZERO_PRODUCTS);
    (WORDS + 2 * index, WORDS + 2 * index + 1)
}
pub const SUPPORT_PAIRS: usize = ZERO_PRODUCTS;
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
        4096,
        WORDS,
        BOOLEANS,
        LOOKUPS,
        1024,
        256,
        114,
        96,
        16,
        7,
        32,
    ]
}
pub fn lookup(index: usize) -> (usize, u128) {
    if index < WORDS {
        return (index, 1);
    }
    let narrow = index - WORDS;
    if narrow < 24 {
        (30 + 10 * narrow, 512)
    } else if narrow < 44 {
        let offset = narrow - 24;
        (264 + 7 * (offset / 2) + 3 * (offset % 2), 512)
    } else {
        assert_eq!(narrow, 44);
        (332, 512)
    }
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
