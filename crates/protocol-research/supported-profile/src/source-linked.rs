//! The setup relation extended with its original encrypted source.
use crate::{
    AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, DEGREE, Profile, auxiliary_modulus,
    relation::{Relation, setup_relation},
};
pub const CIPHERTEXT_POLYNOMIALS: usize = 2;
pub const SOURCE_POLYNOMIALS: usize = 2 * CIPHERTEXT_POLYNOMIALS;
pub const SOURCE_PLAINTEXT_MODULUS: usize = 769;
pub const ADDED_WORDS: usize = 2 * CIPHERTEXT_POLYNOMIALS;
const ADDED_BOOLEANS: usize = 2;
pub fn remap(column: usize, old_words: usize) -> usize {
    if column < old_words {
        column
    } else {
        column + ADDED_WORDS
    }
}
fn signed_words(bits: usize) -> usize {
    if bits < 16 { 1 } else { bits / 16 }
}

/// The existing native word holding the first encryption error plus 64.
/// Sparse columns precede it only in the Boolean bank, not the word bank.
pub fn original_error_column(profile: Profile) -> usize {
    profile.sharing_degree()
        * (signed_words(profile.share_limb_bits())
            + signed_words(profile.sharing_coefficient_bits() - profile.share_limb_bits()))
        + profile.fhe_limbs()
}

pub fn relation(profile: Profile) -> Relation {
    let mut result = setup_relation(profile);
    let old_words = result.words;
    let old_booleans = result.booleans;
    result.tag = b"encrypted-source-linked-setup";
    result.words += ADDED_WORDS;
    result.booleans += ADDED_BOOLEANS;
    for (positive, negative) in &mut result.zero_product_pairs {
        *positive = remap(*positive, old_words);
        *negative = remap(*negative, old_words);
    }
    let ephemeral = result.words + old_booleans;
    result.zero_product_pairs.push((ephemeral, ephemeral + 1));
    result
        .supports
        .push((1, (AUXILIARY_SECRET_SUPPORT / 2) as u64));
    for component in 0..CIPHERTEXT_POLYNOMIALS {
        result.narrow.push((old_words + 2 * component + 1, 512));
    }
    result.parameters[1] = result.words;
    result.parameters[2] = result.booleans;
    result.parameters[3] = result.lookups();
    result.parameters.extend([
        AUXILIARY_DEGREE,
        AUXILIARY_SECRET_SUPPORT,
        SOURCE_PLAINTEXT_MODULUS,
        72,
    ]);
    result
        .parameters
        .extend(auxiliary_modulus().iter().map(|byte| usize::from(*byte)));
    result.message_bytes = result.minimum_message_bytes();
    result
}

pub fn statement_length(profile: Profile) -> usize {
    profile.setup_statement_length() + SOURCE_POLYNOMIALS * DEGREE * (1 + auxiliary_modulus().len())
}
