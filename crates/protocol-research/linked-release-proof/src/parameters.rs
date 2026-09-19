pub const SYSTEMATIC: usize = 65_536;
pub const DOMAIN: usize = 4 * SYSTEMATIC;
pub const QUERY_COUNT: usize = 704;
pub const MASKS: usize = 2 * QUERY_COUNT + 1;
pub const WIDTHS: [usize; 14] = [16, 16, 7, 120, 24, 16, 30, 168, 144, 72, 72, 72, 72, 72];
pub const STARTS: [usize; 14] = [0, 1, 2, 3, 11, 13, 14, 16, 27, 36, 41, 46, 51, 56];
pub const WORDS: usize = 61;
pub const BOOLEANS: usize = 2;
pub const COLUMNS: usize = WORDS + BOOLEANS;
pub const LOOKUPS: usize = 71;
pub const ZERO_PRODUCTS: usize = 1;
pub const SUPPORT_PAIRS: usize = 1;
pub const MAX_DEGREE: usize = 2 * SYSTEMATIC - 1;
pub const WITNESS_DEGREE: usize = SYSTEMATIC + MASKS - 1;
pub const SUM_DEGREE: usize = 2 * SYSTEMATIC + MASKS - 2;
pub const ORACLES: usize = COLUMNS + LOOKUPS + 4 + BOOLEANS + ZERO_PRODUCTS + LOOKUPS + 2;
pub const MESSAGE_BYTES: usize = 262_144;
pub const FIRST_WIDTH: usize = (COLUMNS + 1) * 16 + 48;
pub const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub const RELATION_TAG: &[u8] = b"linked-threshold-release/1";
pub const WITNESS_MAGIC: &[u8; 4] = b"LRW1";
pub const HEADER_BYTES: usize = 198;
pub const MAXIMUM_PROOF_BYTES: usize = 14_439_264;
pub const STATEMENT_PARTS: usize = 1;
pub const STATEMENT_BYTES: usize = HEADER_BYTES + 4 * SYSTEMATIC * 21 + 2 * SYSTEMATIC * 25;
pub fn support(pair: usize) -> (usize, u64) {
    assert_eq!(pair, 0);
    (1, 128)
}
pub fn zero_product_columns(index: usize) -> (usize, usize) {
    assert_eq!(index, 0);
    (61, 62)
}
pub fn lookup(index: usize) -> (usize, u128) {
    if index < WORDS {
        return (index, 1);
    }
    WIDTHS
        .iter()
        .enumerate()
        .filter(|(_, bits)| **bits % 16 != 0)
        .map(|(variable, bits)| {
            (
                STARTS[variable] + bits.div_ceil(16) - 1,
                1u128 << (16 - bits % 16),
            )
        })
        .nth(index - WORDS)
        .expect("Lookup index")
}
pub fn relation_parameters() -> Vec<usize> {
    [
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
        256,
        96,
        48,
        4,
        4,
    ]
    .into_iter()
    .chain(WIDTHS)
    .chain(crate::statement::modulus_parameters())
    .collect()
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
