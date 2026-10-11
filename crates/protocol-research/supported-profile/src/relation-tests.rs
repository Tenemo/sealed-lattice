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
        (331, 24, 375, 12, 12, 1147)
    );
    assert_eq!(
        setup.relation_parameters(),
        [
            65_536, 704, 1_409, 262_144, 131_071, 2, 262_144, 65_536, 331, 24, 375, 1_024, 256,
            112, 96, 16, 7, 32
        ]
    );
    assert_eq!(
        setup.statement_bytes(),
        136 + 42 * 65_536 * 109 + 31 * 65_536 * 21
    );
    assert_eq!(setup.zero_product_columns(11), (353, 354));
    assert_eq!(setup.support(11), (1, 128));
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
        59,
        2,
        68,
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
        144,
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
            59,
            vec![
                (2, 512),
                (11, 256),
                (14, 4),
                (38, 256),
                (43, 256),
                (48, 256),
                (53, 256),
                (58, 256),
            ],
            14_123_872,
        ),
        (
            10,
            10,
            59,
            vec![
                (2, 512),
                (10, 256),
                (12, 256),
                (15, 4),
                (38, 256),
                (43, 256),
                (48, 256),
                (53, 256),
                (58, 256),
            ],
            14_191_456,
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
                (25, 256),
                (39, 256),
                (44, 256),
                (49, 256),
                (54, 256),
                (59, 256),
            ],
            14_349_152,
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
            15_070_048,
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
            29,
            [(10, 512), (21, 512), (26, 512), (28, 512), (24, 7_281)],
            [(29, 30), (31, 32), (22, 33)],
            11_285_344,
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
