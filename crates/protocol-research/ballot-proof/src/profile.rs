pub(crate) const H: usize = 65536;
pub(crate) const D: usize = 4 * H;
pub(crate) const QUERIES: usize = 704;
pub(crate) const MASKS: usize = 2 * QUERIES + 1;
pub(crate) const WORDS: usize = 27;
pub(crate) const BOOLS: usize = 5;
pub(crate) const COLS: usize = WORDS + BOOLS;
pub(crate) const LOOKUPS: usize = 32;
pub(crate) const ZERO_PRODUCTS: usize = 3;
pub(crate) const ORIGINAL: usize = COLS + LOOKUPS + 4;
pub(crate) const ORACLES: usize = ORIGINAL + BOOLS + ZERO_PRODUCTS + LOOKUPS + 2;
pub(crate) const WITNESS_DEGREE: usize = H + MASKS - 1;
pub(crate) const MAX_DEGREE: usize = 2 * H - 1;
pub(crate) const FOLDS: usize = (D / 2).ilog2() as usize;
pub(crate) const MESSAGE_BYTES: usize = 262144;
pub(crate) const FIRST_WIDTH: usize = (COLS + 1) * 16 + 48;
pub(crate) const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub(crate) const STATEMENT_LENGTH: usize = 136 + 4 * H * 109 + 4 * 4096 * 6;
pub(crate) const PROOF_MAGIC: &[u8; 4] = b"LBP1";
pub(crate) const RELATION_TAG: &[u8] = b"linked-scored-ballot/1";
pub(crate) fn lookup(index: usize) -> (usize, u128) {
    if index < WORDS {
        (index, 1)
    } else {
        [(9, 512), (19, 512), (24, 512), (26, 512), (22, 7281)][index - WORDS]
    }
}
pub(crate) fn zero_product_columns(index: usize) -> (usize, usize) {
    [(27, 28), (29, 30), (20, 31)][index]
}
pub(crate) fn relation_parameters() -> Vec<usize> {
    vec![
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
