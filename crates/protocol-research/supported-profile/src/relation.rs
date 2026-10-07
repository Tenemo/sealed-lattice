//! Word relations: each proof's witness columns, lookups and disjoint pairs,
//! and the parameters its context binds. Provers and verifiers take every
//! relation's layout from here.

use crate::{
    AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, DEGREE, FHE_SECRET_SUPPORT, MAXIMUM_SCORE, Profile,
    RECIPIENT_SECRET_SUPPORT, RELEASE_DECODING_LIMB_BITS, RELEASE_LIMB_BITS, SETUP_ERROR_BITS,
    SETUP_QUOTIENT_BITS, SHARE_EPHEMERAL_SUPPORT, SHARE_SCALE, WORD_BITS, auxiliary_modulus,
    share_modulus,
};

/// Witness columns have one row per ring coefficient.
pub const SYSTEMATIC: usize = DEGREE;
pub const DOMAIN: usize = 4 * SYSTEMATIC;
pub const QUERY_COUNT: usize = 704;
pub const MASKS: usize = 2 * QUERY_COUNT + 1;
pub const MAX_DEGREE: usize = 2 * SYSTEMATIC - 1;
pub const WITNESS_DEGREE: usize = SYSTEMATIC + MASKS - 1;
pub const SUM_DEGREE: usize = 2 * SYSTEMATIC + MASKS - 2;
/// Folding halves the evaluation domain down to two points.
pub const FOLDS: usize = (DOMAIN / 2).ilog2() as usize;
const DIGEST_BYTES: usize = 64;
const SALT_BYTES: usize = 128;
/// The prover draws uniform field elements as candidate words of this many
/// bytes, read in blocks of this many bytes.
pub const RANDOM_WORD_BYTES: usize = 16;
pub const RANDOM_READ_BYTES: usize = 65_536;
const EXTENSION_BYTES: usize = 48;
/// The proof header: its magic, the statement and context digests, three
/// oracle roots, the mask sum, a salt per round, the fold roots and the
/// terminal value.
pub const PROOF_HEADER_BYTES: usize = 4
    + 5 * DIGEST_BYTES
    + EXTENSION_BYTES
    + (FOLDS + 3) * SALT_BYTES
    + (FOLDS - 1) * DIGEST_BYTES
    + EXTENSION_BYTES;
/// Challenges fill messages of this many bytes unless a relation needs more.
const MESSAGE_BYTES: usize = 262_144;
/// Registration, ballot and release statement headers.
pub const BALLOT_HEADER_BYTES: usize = 4 + 2 * DIGEST_BYTES + 2 + 1 + 1;
pub const RELEASE_HEADER_BYTES: usize = 4 + 3 * DIGEST_BYTES + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    /// The domain tag of the relation's proofs and their encoding's magic.
    pub tag: &'static [u8],
    pub proof_magic: &'static [u8; 4],
    pub words: usize,
    pub booleans: usize,
    /// Lookups after the whole words: each narrow column and the factor
    /// that scales it to a whole word.
    pub narrow: Vec<(usize, u128)>,
    /// Column pairs whose products vanish.
    pub zero_product_pairs: Vec<(usize, usize)>,
    /// The first zero-product pairs are sparse secrets' positive and
    /// negative supports: each has a ring-degree stride and the size of each
    /// half of its support.
    pub supports: Vec<(usize, u64)>,
    pub message_bytes: usize,
    pub statement_bytes: usize,
    /// Relation parameters after the shared proof parameters.
    pub parameters: Vec<usize>,
}
impl Relation {
    pub fn words(&self) -> usize {
        self.words
    }
    pub fn booleans(&self) -> usize {
        self.booleans
    }
    pub fn columns(&self) -> usize {
        self.words + self.booleans
    }
    pub fn lookups(&self) -> usize {
        self.words + self.narrow.len()
    }
    /// A lookup's column and the factor that scales it to a whole word.
    pub fn lookup(&self, index: usize) -> (usize, u128) {
        if index < self.words {
            (index, 1)
        } else {
            self.narrow[index - self.words]
        }
    }
    pub fn zero_products(&self) -> usize {
        self.zero_product_pairs.len()
    }
    pub fn zero_product_columns(&self, index: usize) -> (usize, usize) {
        self.zero_product_pairs[index]
    }
    pub fn support_pairs(&self) -> usize {
        self.supports.len()
    }
    pub fn support(&self, pair: usize) -> (usize, u64) {
        self.supports[pair]
    }
    pub fn message_bytes(&self) -> usize {
        self.message_bytes
    }
    pub fn statement_bytes(&self) -> usize {
        self.statement_bytes
    }
    /// Committed oracles: the columns, the multiplicities, each lookup's
    /// reciprocals, the table reciprocals, the sum mask and the affine
    /// quotient.
    pub fn original_oracles(&self) -> usize {
        self.columns() + self.lookups() + 4
    }
    /// The committed oracles, then the Boolean, zero-product, lookup and
    /// table residuals and the affine remainder.
    pub fn oracles(&self) -> usize {
        self.original_oracles() + self.booleans + self.zero_products() + self.lookups() + 2
    }
    pub fn first_width(&self) -> usize {
        (self.columns() + 1) * 16 + EXTENSION_BYTES
    }
    pub fn second_width(&self) -> usize {
        (self.lookups() + 2) * EXTENSION_BYTES
    }
    /// The least power of two holding every combination challenge, every
    /// query index and the widest leaf.
    pub fn minimum_message_bytes(&self) -> usize {
        (96 * (2 * self.oracles() + 1))
            .max(4 * QUERY_COUNT)
            .max(self.second_width())
            .next_power_of_two()
    }
    pub fn relation_parameters(&self) -> Vec<usize> {
        [
            SYSTEMATIC,
            QUERY_COUNT,
            MASKS,
            DOMAIN,
            MAX_DEGREE,
            2,
            self.message_bytes,
        ]
        .into_iter()
        .chain(self.parameters.iter().copied())
        .collect()
    }
    pub fn degrees(&self) -> Vec<usize> {
        let mut degrees = vec![WITNESS_DEGREE; self.columns() + self.lookups() + 3];
        degrees.push(SUM_DEGREE - SYSTEMATIC);
        degrees.extend(vec![
            2 * WITNESS_DEGREE - SYSTEMATIC;
            self.booleans + self.zero_products() + self.lookups()
        ]);
        degrees.extend([WITNESS_DEGREE - 1, SYSTEMATIC - 2]);
        assert_eq!(degrees.len(), self.oracles());
        degrees
    }
    /// Bytes of the largest canonical proof: the header, then each stage's
    /// multiproof with every query's opening and at most one sibling per
    /// parent a query can reach.
    pub fn maximum_proof_bytes(&self) -> usize {
        let multiproof = |length: usize, width: usize| {
            let openings = (2 * QUERY_COUNT).min(length);
            let siblings: usize = (1..=length.ilog2())
                .map(|level| openings.min(length >> level))
                .sum();
            4 + openings * (4 + width + SALT_BYTES) + siblings * DIGEST_BYTES
        };
        let mut total = PROOF_HEADER_BYTES;
        for width in [self.first_width(), self.second_width(), EXTENSION_BYTES] {
            total += multiproof(DOMAIN, width);
        }
        let mut length = DOMAIN / 2;
        while length > 2 {
            total += multiproof(length, EXTENSION_BYTES);
            length /= 2;
        }
        total
    }
}

fn narrow_factor(bits: usize) -> u128 {
    1 << (WORD_BITS - bits)
}
fn half_support(stride: usize, support: usize) -> (usize, u64) {
    (stride, (support / 2) as u64)
}

/// The complete setup contribution relation of one profile. Each sparse
/// secret's positive and negative supports are one disjoint pair, and each
/// narrow word is scaled to a whole word.
pub fn setup_relation(profile: Profile) -> Relation {
    let shape = profile.setup_shape();
    let words = shape.word_columns;
    let mut relation = Relation {
        tag: b"complete-setup-words/2",
        proof_magic: b"SWP3",
        words,
        booleans: shape.boolean_columns,
        narrow: shape
            .narrow_words
            .iter()
            .map(|(column, bits)| (*column, narrow_factor(*bits)))
            .collect(),
        zero_product_pairs: (0..shape.sparse_supports.len())
            .map(|pair| (words + 2 * pair, words + 2 * pair + 1))
            .collect(),
        supports: shape
            .sparse_supports
            .iter()
            .map(|(stride, half)| (*stride, *half as u64))
            .collect(),
        message_bytes: 0,
        statement_bytes: profile.setup_statement_length(),
        parameters: Vec::new(),
    };
    relation.message_bytes = relation.minimum_message_bytes();
    relation.parameters = vec![
        DEGREE,
        relation.words(),
        relation.booleans(),
        relation.lookups(),
        FHE_SECRET_SUPPORT,
        SHARE_EPHEMERAL_SUPPORT,
        profile.sharing_coefficient_bits(),
        profile.share_limb_bits(),
        SETUP_QUOTIENT_BITS,
        SETUP_ERROR_BITS,
        profile.share_carry_bits(),
    ];
    relation
}

/// Word columns of the ballot relation: each FHE ciphertext component's
/// quotient, carries and error, the packed plaintext's lower word, the
/// packing quotient, the scores less one, and each auxiliary component's
/// quotient and error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BallotColumns {
    limbs: usize,
}
impl BallotColumns {
    pub fn new(profile: Profile) -> Self {
        Self {
            limbs: profile.fhe_limbs(),
        }
    }
    pub fn fhe_quotient(self, component: usize) -> usize {
        assert!(component < 2);
        component * (self.limbs + 1)
    }
    pub fn fhe_carry(self, component: usize, carry: usize) -> usize {
        assert!(carry + 1 < self.limbs);
        self.fhe_quotient(component) + 1 + carry
    }
    pub fn fhe_error(self, component: usize) -> usize {
        self.fhe_quotient(component) + self.limbs
    }
    pub fn plaintext(self) -> usize {
        2 * (self.limbs + 1)
    }
    pub fn packing_quotient(self) -> usize {
        self.plaintext() + 1
    }
    pub fn scores(self) -> usize {
        self.plaintext() + 2
    }
    pub fn auxiliary_quotient(self, component: usize) -> usize {
        assert!(component < 2);
        self.scores() + 1 + 2 * component
    }
    pub fn auxiliary_error(self, component: usize) -> usize {
        self.auxiliary_quotient(component) + 1
    }
    pub fn words(self) -> usize {
        self.scores() + 5
    }
    /// The FHE and auxiliary ephemerals' positive and negative supports, then
    /// the packed plaintext's high bit.
    pub fn fhe_positive(self) -> usize {
        self.words()
    }
    pub fn auxiliary_positive(self) -> usize {
        self.words() + 2
    }
    pub fn plaintext_high_bit(self) -> usize {
        self.words() + 4
    }
    pub fn fhe_limbs(self) -> usize {
        self.limbs
    }
}

/// The linked ballot relation of one profile.
pub fn ballot_relation(profile: Profile) -> Relation {
    let columns = BallotColumns::new(profile);
    let words = columns.words();
    let error = narrow_factor(SETUP_ERROR_BITS);
    let mut relation = Relation {
        tag: b"linked-scored-ballot/1",
        proof_magic: b"LBP1",
        words,
        booleans: 5,
        narrow: vec![
            (columns.fhe_error(0), error),
            (columns.fhe_error(1), error),
            (columns.auxiliary_error(0), error),
            (columns.auxiliary_error(1), error),
            // Scores less one are at most MAXIMUM_SCORE - 1.
            (
                columns.scores(),
                (((1 << WORD_BITS) - 1) / (MAXIMUM_SCORE - 1)) as u128,
            ),
        ],
        zero_product_pairs: vec![
            (columns.fhe_positive(), columns.fhe_positive() + 1),
            (
                columns.auxiliary_positive(),
                columns.auxiliary_positive() + 1,
            ),
            (columns.plaintext(), columns.plaintext_high_bit()),
        ],
        supports: vec![
            half_support(1, FHE_SECRET_SUPPORT),
            half_support(DEGREE / AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT),
        ],
        message_bytes: MESSAGE_BYTES,
        statement_bytes: BALLOT_HEADER_BYTES
            + 4 * DEGREE * (1 + profile.ciphertext_modulus().byte_length())
            + 4 * AUXILIARY_DEGREE * (1 + auxiliary_modulus().len()),
        parameters: Vec::new(),
    };
    relation.parameters = vec![
        relation.words(),
        relation.booleans(),
        relation.lookups(),
        FHE_SECRET_SUPPORT,
        AUXILIARY_SECRET_SUPPORT,
        1 << (WORD_BITS - 1),
        1 << WORD_BITS,
    ];
    for (left, right) in relation.zero_product_pairs.clone() {
        relation.parameters.extend([left, right]);
    }
    relation
}

/// The first word column of each signed release variable, in the order of
/// `Profile::release_variable_bits`, and the total word count.
pub fn release_variable_starts(profile: Profile) -> (Vec<usize>, usize) {
    let mut words = 0;
    let starts = profile
        .release_variable_bits()
        .into_iter()
        .map(|bits| {
            let start = words;
            words += bits.div_ceil(WORD_BITS);
            start
        })
        .collect();
    (starts, words)
}

/// The share scale and the share and release moduli in 32-bit words, each
/// after its byte width.
pub fn release_modulus_parameters(profile: Profile) -> Vec<usize> {
    let mut values = vec![SHARE_SCALE as usize];
    for mut bytes in [
        share_modulus().to_vec(),
        profile.release_modulus().to_bytes(),
    ] {
        let width = bytes.len().next_multiple_of(4);
        bytes.resize(width, 0);
        values.push(width);
        values.extend(
            bytes
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()) as usize),
        );
    }
    values
}

/// The linked release relation of one profile: every signed release
/// variable in whole words, each narrower top word scaled to a whole word,
/// and the recipient secret's supports.
pub fn release_relation(profile: Profile) -> Relation {
    let bits = profile.release_variable_bits();
    let (starts, words) = release_variable_starts(profile);
    let mut relation = Relation {
        tag: b"linked-threshold-release/1",
        proof_magic: b"LRP1",
        words,
        booleans: 2,
        narrow: bits
            .iter()
            .zip(&starts)
            .filter(|(bits, _)| **bits % WORD_BITS != 0)
            .map(|(bits, start)| {
                (
                    start + bits.div_ceil(WORD_BITS) - 1,
                    narrow_factor(bits % WORD_BITS),
                )
            })
            .collect(),
        zero_product_pairs: vec![(words, words + 1)],
        supports: vec![half_support(1, RECIPIENT_SECRET_SUPPORT)],
        message_bytes: MESSAGE_BYTES,
        statement_bytes: RELEASE_HEADER_BYTES
            + 4 * DEGREE * (1 + share_modulus().len())
            + 2 * DEGREE * (1 + profile.release_modulus().byte_length()),
        parameters: Vec::new(),
    };
    relation.parameters = vec![
        relation.words(),
        relation.booleans(),
        relation.lookups(),
        RECIPIENT_SECRET_SUPPORT,
        RELEASE_DECODING_LIMB_BITS,
        RELEASE_LIMB_BITS,
        profile.clearing_factor(),
        profile.release_public_limbs(),
    ];
    relation.parameters.extend(bits);
    relation
        .parameters
        .extend(release_modulus_parameters(profile));
    relation
}

#[cfg(test)]
#[path = "relation-tests.rs"]
mod tests;
