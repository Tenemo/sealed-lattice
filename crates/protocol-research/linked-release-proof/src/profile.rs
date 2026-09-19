pub(crate) const H: usize = 65536;
pub(crate) const D: usize = 4 * H;
pub(crate) const QUERIES: usize = 704;
pub(crate) const MASKS: usize = 2 * QUERIES + 1;
pub(crate) const WORDS: usize = 61;
pub(crate) const BOOLS: usize = 2;
pub(crate) const COLS: usize = WORDS + BOOLS;
pub(crate) const LOOKUPS: usize = 71;
pub(crate) const ZERO_PRODUCTS: usize = 1;
pub(crate) const ORIGINAL: usize = COLS + LOOKUPS + 4;
pub(crate) const ORACLES: usize = ORIGINAL + BOOLS + ZERO_PRODUCTS + LOOKUPS + 2;
pub(crate) const WITNESS_DEGREE: usize = H + MASKS - 1;
pub(crate) const MAX_DEGREE: usize = 2 * H - 1;
pub(crate) const FOLDS: usize = (D / 2).ilog2() as usize;
pub(crate) const MESSAGE_BYTES: usize = 262144;
pub(crate) const FIRST_WIDTH: usize = (COLS + 1) * 16 + 48;
pub(crate) const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub(crate) const STATEMENT_LENGTH: usize = 198 + 4 * H * 21 + 2 * H * 25;
pub(crate) const PROOF_MAGIC: &[u8; 4] = b"LRP1";
pub(crate) const RELATION_TAG: &[u8] = b"linked-threshold-release/1";
pub(crate) fn lookup(index: usize) -> (usize, u128) {
    if index < WORDS {
        return (index, 1);
    }
    [
        (2, 512),
        (10, 256),
        (12, 256),
        (15, 4),
        (26, 256),
        (40, 256),
        (45, 256),
        (50, 256),
        (55, 256),
        (60, 256),
    ][index - WORDS]
}
pub(crate) fn zero_product_columns(index: usize) -> (usize, usize) {
    assert_eq!(index, 0);
    (61, 62)
}
pub(crate) fn relation_parameters() -> Vec<usize> {
    let mut values = vec![
        H,
        QUERIES,
        MASKS,
        D,
        MAX_DEGREE,
        2,
        MESSAGE_BYTES,
        WORDS,
        BOOLS,
        LOOKUPS,
        256,
        96,
        48,
        4,
        4,
        16,
        16,
        7,
        120,
        24,
        16,
        30,
        168,
        144,
        72,
        72,
        72,
        72,
        72,
    ];
    values.extend(crate::statement::modulus_parameters());
    values
}
