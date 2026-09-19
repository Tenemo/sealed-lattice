pub(crate) const H: usize = 65536;
pub(crate) const D: usize = 4 * H;
pub(crate) const QUERIES: usize = 704;
pub(crate) const MASKS: usize = 2 * QUERIES + 1;
pub(crate) const WORDS: usize = 333;
pub(crate) const BOOLS: usize = 32;
pub(crate) const COLS: usize = WORDS + BOOLS;
pub(crate) const LOOKUPS: usize = 378;
pub(crate) const ORIGINAL: usize = COLS + LOOKUPS + 4;
pub(crate) const ORACLES: usize = ORIGINAL + BOOLS + ZERO_PRODUCTS + LOOKUPS + 2;
pub(crate) const WITNESS_DEGREE: usize = H + MASKS - 1;
pub(crate) const MAX_DEGREE: usize = 2 * H - 1;
pub(crate) const FOLDS: usize = (D / 2).ilog2() as usize;
pub(crate) const MESSAGE_BYTES: usize = 262144;
pub(crate) const FIRST_WIDTH: usize = (COLS + 1) * 16 + 48;
pub(crate) const SECOND_WIDTH: usize = (LOOKUPS + 2) * 48;
pub(crate) const STATEMENT_LENGTH: usize = 145 + 42 * H * 109 + 31 * H * 21 + 2 * 4096 * 6;
pub(crate) const ZERO_PRODUCTS: usize = 13;
pub(crate) const PROOF_MAGIC: &[u8; 4] = b"SWP2";
pub(crate) const RELATION_TAG: &[u8] = b"complete-setup-words/1";
pub(crate) fn lookup(index: usize) -> (usize, u128) {
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
        (332, 512)
    }
}

pub(crate) fn zero_product_columns(index: usize) -> (usize, usize) {
    assert!(index < ZERO_PRODUCTS);
    (WORDS + 2 * index, WORDS + 2 * index + 1)
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
        H,
        4096,
        WORDS,
        BOOLS,
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
