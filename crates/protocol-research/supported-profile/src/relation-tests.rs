use super::*;

#[test]
fn completion_relations_keep_their_bound_parameters() {
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
        (415, 24, 471, 12, 12, 1423 + 2 * (4 * 9 - 1) * 8)
    );
    assert_eq!(
        setup.relation_parameters(),
        [
            65_536, 704, 1_409, 262_144, 131_071, 2, 524_288, 65_536, 415, 24, 471, 1_024, 256,
            112, 96, 16, 7, 32
        ]
    );
    assert_eq!(setup.zero_product_columns(11), (437, 438));
    assert_eq!(setup.support(11), (1, 128));
    let ballot = ballot_relation(completion);
    assert_eq!(
        ballot.relation_parameters()[7..],
        [26, 4, 31, 1_024, 256, 6_144, 12_288, 26, 27, 28, 29]
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
    // the release modulus 12289 * 349239 * 2^160 + 1 in 32-bit words.
    let share = share_modulus();
    expected.extend(
        share
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()) as usize),
    );
    expected.extend([24, 1, 0, 0, 0, 0, 12_289 * 349_239]);
    assert_eq!(release.relation_parameters()[7..], expected);
    assert_eq!(PROOF_HEADER_BYTES, 3_936);
}

// Word, lookup and narrow counts and the largest proofs of the model
// owners' column layouts.
#[test]
fn layouts_match_the_model_census() {
    for (participants, options, words, narrow, maximum) in [
        (
            3,
            2,
            52,
            vec![
                (2, 512),
                (11, 256),
                (14, 4),
                (36, 256),
                (41, 256),
                (46, 256),
                (51, 256),
            ],
            13_425_436,
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
            14_439_196,
        ),
        (
            16,
            2,
            60,
            vec![
                (2, 512),
                (10, 256),
                (12, 256),
                (15, 4),
                (39, 256),
                (44, 256),
                (49, 256),
                (54, 256),
                (59, 256),
            ],
            14_281_500,
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
                (42, 256),
                (47, 256),
                (52, 256),
                (57, 256),
                (62, 256),
                (67, 256),
            ],
            15_069_980,
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
            22,
            [(6, 512), (13, 512), (19, 512), (21, 512), (17, 7_281)],
            [(22, 23), (24, 25)],
            10_631_964,
        ),
        (
            10,
            10,
            26,
            [(8, 512), (17, 512), (23, 512), (25, 512), (21, 7_281)],
            [(26, 27), (28, 29)],
            10_992_412,
        ),
        (
            16,
            2,
            24,
            [(7, 512), (15, 512), (21, 512), (23, 512), (19, 7_281)],
            [(24, 25), (26, 27)],
            10_812_188,
        ),
        (
            20,
            20,
            30,
            [(10, 512), (21, 512), (27, 512), (29, 512), (25, 7_281)],
            [(30, 31), (32, 33)],
            11_352_860,
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
    let mut relations = Vec::new();
    for profile in Profile::all() {
        relations.extend([
            setup_relation(profile),
            ballot_relation(profile),
            release_relation(profile),
        ]);
        assert_eq!(
            setup_relation(profile).support_pairs(),
            profile.participants() + 2
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
    // Three participants have twelve-bit high sharing parts.
    let small = setup_relation(Profile::new(3, 2).unwrap());
    assert_eq!(small.lookup(small.words()), (6, 16));
}
