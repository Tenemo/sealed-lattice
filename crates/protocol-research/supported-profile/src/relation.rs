//! Word relations: each proof's witness columns, lookups and disjoint pairs,
//! and the parameters its context binds. Provers and verifiers take every
//! relation's layout from here.

use crate::{
    AUXILIARY_DEGREE, AUXILIARY_SECRET_SUPPORT, DEGREE, FHE_LIMB_BITS, FHE_SECRET_SUPPORT,
    MAXIMUM_SCORE, Profile, RECIPIENT_SECRET_SUPPORT, RELEASE_DECODING_LIMB_BITS,
    RELEASE_LIMB_BITS, SETUP_ERROR_BITS, SETUP_QUOTIENT_BITS, SHARE_EPHEMERAL_SUPPORT, SHARE_SCALE,
    WORD_BITS, auxiliary_modulus, share_modulus,
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
const REGISTRATION_HEADER_BYTES: usize = 8 + 20;
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
    /// The random bytes a proof requests when no candidate word is rejected:
    /// a salt for every leaf of the three oracle trees and of each fold tree
    /// and for every transcript round, and whole reads for the first
    /// oracle's column masks and degree mask and the second oracle's lookup
    /// masks and sum mask.
    pub fn minimum_random_bytes(&self) -> usize {
        let reads = |words: usize| (words * RANDOM_WORD_BYTES).next_multiple_of(RANDOM_READ_BYTES);
        let mut leaves = 3 * DOMAIN;
        let mut length = DOMAIN / 2;
        while length > 2 {
            leaves += length;
            length /= 2;
        }
        (leaves + FOLDS + 3) * SALT_BYTES
            + (self.columns() + 1) * reads(MASKS)
            + reads(3 * (MAX_DEGREE + 1))
            + (self.lookups() + 1) * reads(3 * MASKS)
            + reads(3 * (WITNESS_DEGREE + 1))
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

/// The registration key relation: its quotient, carry and error words and
/// the positive and negative supports of the recipient's secret. It precedes
/// the roster, so every profile shares it.
pub fn registration_relation() -> Relation {
    let mut relation = Relation {
        tag: b"recipient-registration-key/1",
        proof_magic: b"RWP1",
        words: 3,
        booleans: 2,
        narrow: vec![(2, narrow_factor(SETUP_ERROR_BITS))],
        zero_product_pairs: vec![(3, 4)],
        supports: vec![half_support(1, RECIPIENT_SECRET_SUPPORT)],
        message_bytes: MESSAGE_BYTES,
        statement_bytes: REGISTRATION_HEADER_BYTES + 2 * DEGREE * (1 + share_modulus().len()),
        parameters: Vec::new(),
    };
    relation.parameters = vec![
        SYSTEMATIC,
        relation.words(),
        relation.booleans(),
        relation.lookups(),
        RECIPIENT_SECRET_SUPPORT,
        FHE_LIMB_BITS,
        SETUP_QUOTIENT_BITS,
        SETUP_ERROR_BITS,
    ];
    relation
}

/// The complete setup contribution relation of one profile. Each sparse
/// secret's positive and negative supports are one disjoint pair, and each
/// narrow word is scaled to a whole word.
pub fn setup_relation(profile: Profile) -> Relation {
    let shape = profile.setup_shape();
    let words = shape.word_columns;
    let mut relation = Relation {
        tag: b"complete-setup-words/1",
        proof_magic: b"SWP2",
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
        AUXILIARY_DEGREE,
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
    /// The FHE and auxiliary secrets' positive and negative supports, then
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
mod tests {
    use super::*;

    #[test]
    fn completion_relations_keep_their_bound_parameters() {
        let registration = registration_relation();
        assert_eq!(
            registration.relation_parameters(),
            [
                65_536, 704, 1_409, 262_144, 131_071, 2, 262_144, 65_536, 3, 2, 4, 256, 96, 16, 7
            ]
        );
        assert_eq!(
            (
                registration.oracles(),
                registration.first_width(),
                registration.second_width(),
                registration.statement_bytes()
            ),
            (22, 144, 288, 28 + 2 * 65_536 * 21)
        );
        let completion = Profile::new(10, 10).unwrap();
        let setup = setup_relation(completion);
        assert_eq!(
            (
                setup.words(),
                setup.booleans(),
                setup.lookups(),
                setup.zero_products(),
                setup.support_pairs(),
                setup.oracles(),
            ),
            (333, 32, 378, 13, 13, 1172)
        );
        assert_eq!(
            setup.relation_parameters(),
            [
                65_536, 704, 1_409, 262_144, 131_071, 2, 262_144, 65_536, 4_096, 333, 32, 378,
                1_024, 256, 114, 96, 16, 7, 32
            ]
        );
        assert_eq!(
            setup.statement_bytes(),
            145 + 42 * 65_536 * 109 + 31 * 65_536 * 21 + 2 * 4_096 * 6
        );
        assert_eq!(setup.zero_product_columns(12), (357, 358));
        assert_eq!(setup.support(12), (16, 128));
        let ballot = ballot_relation(completion);
        assert_eq!(
            ballot.relation_parameters()[7..],
            [
                27, 5, 32, 1_024, 256, 32_768, 65_536, 27, 28, 29, 30, 20, 31
            ]
        );
        assert_eq!(
            ballot.statement_bytes(),
            136 + 4 * 65_536 * 109 + 4 * 4_096 * 6
        );
        assert_eq!(ballot.supports, [(1, 512), (16, 128)]);
        let release = release_relation(completion);
        let mut expected = vec![
            61,
            2,
            71,
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
            998_244_353,
            20,
        ];
        // The share modulus (2^128 - 133 * 2^64 + 1) * (119 * 2^23 + 1) and
        // the release modulus 65537 * 65445 * 2^160 + 1 in 32-bit words.
        let share = share_modulus();
        expected.extend(
            share
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()) as usize),
        );
        expected.extend([24, 1, 0, 0, 0, 0, 65_537 * 65_445]);
        assert_eq!(release.relation_parameters()[7..], expected);
        assert_eq!(
            release.statement_bytes(),
            198 + 4 * 65_536 * 21 + 2 * 65_536 * 25
        );
        assert_eq!(PROOF_HEADER_BYTES, 4_004);
    }

    // Word, lookup and narrow counts and the largest proofs of the model
    // owners' column layouts.
    #[test]
    fn layouts_match_the_model_census() {
        for (participants, options, words, narrow, maximum) in [
            (
                3,
                2,
                60,
                vec![
                    (2, 512),
                    (11, 256),
                    (14, 4),
                    (25, 256),
                    (39, 256),
                    (44, 256),
                    (49, 256),
                    (54, 256),
                    (59, 256),
                ],
                14_281_568,
            ),
            (
                10,
                10,
                61,
                vec![
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
                ],
                14_439_264,
            ),
            (
                16,
                2,
                67,
                vec![
                    (2, 512),
                    (10, 2),
                    (12, 256),
                    (15, 4),
                    (24, 256),
                    (41, 256),
                    (46, 256),
                    (51, 256),
                    (56, 256),
                    (61, 256),
                    (66, 256),
                ],
                15_047_520,
            ),
            (
                20,
                20,
                68,
                vec![
                    (2, 512),
                    (10, 2),
                    (12, 256),
                    (15, 4),
                    (25, 256),
                    (42, 256),
                    (47, 256),
                    (52, 256),
                    (57, 256),
                    (62, 256),
                    (67, 256),
                ],
                15_137_632,
            ),
        ] {
            let release = release_relation(Profile::new(participants, options).unwrap());
            assert_eq!((release.words(), release.narrow.clone()), (words, narrow));
            assert_eq!(release.maximum_proof_bytes(), maximum);
        }
        for (participants, options, words, narrow, zero_products, maximum) in [
            (
                3,
                2,
                21,
                [(6, 512), (13, 512), (18, 512), (20, 512), (16, 7_281)],
                [(21, 22), (23, 24), (14, 25)],
                10_564_448,
            ),
            (
                10,
                10,
                27,
                [(9, 512), (19, 512), (24, 512), (26, 512), (22, 7_281)],
                [(27, 28), (29, 30), (20, 31)],
                11_105_120,
            ),
            (
                16,
                2,
                25,
                [(8, 512), (17, 512), (22, 512), (24, 512), (20, 7_281)],
                [(25, 26), (27, 28), (18, 29)],
                10_924_896,
            ),
            (
                20,
                20,
                31,
                [(11, 512), (23, 512), (28, 512), (30, 512), (26, 7_281)],
                [(31, 32), (33, 34), (24, 35)],
                11_465_568,
            ),
        ] {
            let ballot = ballot_relation(Profile::new(participants, options).unwrap());
            assert_eq!(
                (
                    ballot.words(),
                    ballot.narrow.as_slice(),
                    ballot.zero_product_pairs.as_slice()
                ),
                (words, narrow.as_slice(), zero_products.as_slice())
            );
            assert_eq!(ballot.maximum_proof_bytes(), maximum);
        }
    }

    #[test]
    fn every_relation_fits_its_challenge_messages() {
        let mut relations = vec![registration_relation()];
        for profile in Profile::all() {
            relations.extend([
                setup_relation(profile),
                ballot_relation(profile),
                release_relation(profile),
            ]);
            assert_eq!(
                setup_relation(profile).support_pairs(),
                profile.participants() + 3
            );
        }
        for relation in relations {
            assert_eq!(relation.degrees().len(), relation.oracles());
            assert!(relation.message_bytes().is_power_of_two());
            assert!(relation.message_bytes() >= relation.minimum_message_bytes());
            for index in relation.words()..relation.lookups() {
                let (column, factor) = relation.lookup(index);
                assert!(column < relation.words() && factor > 1 && factor < 1 << WORD_BITS);
            }
            for (left, right) in &relation.zero_product_pairs {
                assert!(left < right && *right < relation.columns());
            }
        }
        // Three participants have thirteen-bit high sharing parts.
        let small = setup_relation(Profile::new(3, 2).unwrap());
        assert_eq!(small.lookup(small.words()), (6, 8));
    }
}
