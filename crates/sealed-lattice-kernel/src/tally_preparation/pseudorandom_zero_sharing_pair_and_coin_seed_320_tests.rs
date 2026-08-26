use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
        CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_BYTE_LENGTH,
        COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN,
        COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH,
        COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN, CollectiveCoinSourceCommitment320,
        CollectiveCoinSourceCoordinate320, CollectiveCoinSourceOpening320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
        PseudorandomZeroSharingPairSeedCommitment320,
        PseudorandomZeroSharingPairSeedContributionCoordinate320,
        PseudorandomZeroSharingPairSeedOpening320,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH, SeedCatalogSecretLeafError320,
        combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320,
        create_collective_coin_source_320,
        create_pseudorandom_zero_sharing_pair_seed_contribution_320,
        verify_collective_coin_source_320,
        verify_collective_coin_source_opening_catalog_inclusion_320,
        verify_pseudorandom_zero_sharing_pair_seed_contribution_320,
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogTree320,
    },
};

#[test]
fn every_admitted_pair_endpoint_and_coin_source_has_exact_canonical_bytes() {
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_BYTE_LENGTH,
        401
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        444
    );
    assert_eq!(COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_BYTE_LENGTH, 385);
    assert_eq!(COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH, 428);

    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let context = preparation_context(participant_count, participant_count as u8);
        let parameter_identity = deterministic_hash(0x11, participant_count);
        for contributor_position in 0..participant_count {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                context,
                contributor_position,
            )
            .unwrap();
            for counterpart_position in 0..participant_count {
                if counterpart_position == contributor_position {
                    continue;
                }
                let coordinate =
                    PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
                        layout,
                        counterpart_position,
                    )
                    .unwrap();
                let contribution =
                    deterministic_bytes::<
                        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
                    >(0x21, contributor_position, counterpart_position);
                let salt = deterministic_bytes::<
                    SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
                >(0x31, contributor_position, counterpart_position);
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_pair_seed_contribution_320(
                        coordinate,
                        contribution,
                        salt,
                    )
                    .unwrap();
                assert_eq!(commitment.coordinate(), coordinate);
                let commitment_bytes = commitment.canonical_bytes().unwrap();
                let opening_bytes = opening.canonical_bytes().unwrap();
                assert_eq!(
                    commitment_bytes.len(),
                    PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_COMMITMENT_OBJECT_BYTE_LENGTH
                );
                assert_eq!(
                    opening_bytes.len(),
                    PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
                );
                assert_eq!(
                    PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(
                        &commitment_bytes
                    )
                    .unwrap(),
                    commitment
                );
                assert_eq!(
                    PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(&opening_bytes)
                        .unwrap(),
                    opening
                );
                let matched = verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
                    coordinate,
                    &commitment_bytes,
                    &opening_bytes,
                )
                .unwrap();
                assert_eq!(matched.coordinate(), coordinate);
            }

            let coordinate =
                CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
            let source = deterministic_bytes::<COLLECTIVE_COIN_SOURCE_BYTE_LENGTH>(
                0x41,
                contributor_position,
                participant_count,
            );
            let salt = deterministic_bytes::<SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH>(
                0x51,
                contributor_position,
                participant_count,
            );
            let (commitment, opening) =
                create_collective_coin_source_320(coordinate, source, salt).unwrap();
            assert_eq!(commitment.coordinate(), coordinate);
            let commitment_bytes = commitment.canonical_bytes().unwrap();
            let opening_bytes = opening.canonical_bytes().unwrap();
            assert_eq!(
                commitment_bytes.len(),
                COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_BYTE_LENGTH
            );
            assert_eq!(
                opening_bytes.len(),
                COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH
            );
            assert_eq!(
                CollectiveCoinSourceCommitment320::from_canonical_bytes(&commitment_bytes).unwrap(),
                commitment
            );
            assert_eq!(
                CollectiveCoinSourceOpening320::from_canonical_bytes(&opening_bytes).unwrap(),
                opening
            );
            let matched =
                verify_collective_coin_source_320(coordinate, &commitment_bytes, &opening_bytes)
                    .unwrap();
            assert_eq!(matched.coordinate(), coordinate);
            assert_eq!(matched.as_bytes(), &source);
        }
    }
}

#[test]
fn pair_and_coin_digests_match_independent_canonical_shake_framing() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0x61);
    let parameter_identity = deterministic_hash(0x63, 0);
    let pair_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 2)
            .unwrap();
    let pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            pair_layout,
            7,
        )
        .unwrap();
    let pair_contribution = [0x65; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH];
    let pair_salt = [0x67; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH];
    let pair_commitment = create_pseudorandom_zero_sharing_pair_seed_contribution_320(
        pair_coordinate,
        pair_contribution,
        pair_salt,
    )
    .unwrap()
    .0;
    let pair_scope = pair_coordinate.scope();
    assert_eq!(
        pair_commitment.digest(),
        independent_secret_leaf_digest(
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
            vec![
                CanonicalItem::hash512(pair_scope.parameter_identity().into_bytes()),
                CanonicalItem::hash512(pair_scope.preparation_context_identity().into_bytes()),
                CanonicalItem::unsigned16(0),
                CanonicalItem::hash512(pair_coordinate.seed_catalog_identity().into_bytes()),
                CanonicalItem::unsigned16(pair_scope.participant_count()),
                CanonicalItem::unsigned16(pair_scope.lower_roster_position()),
                CanonicalItem::unsigned16(pair_scope.upper_roster_position()),
                CanonicalItem::unsigned16(pair_coordinate.contributor_position()),
            ],
            &pair_salt,
            &pair_contribution,
        )
    );

    let coin_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 5)
            .unwrap();
    let coin_coordinate =
        CollectiveCoinSourceCoordinate320::from_catalog_layout(coin_layout).unwrap();
    let coin_source = [0x69; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH];
    let coin_salt = [0x6b; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH];
    let coin_commitment =
        create_collective_coin_source_320(coin_coordinate, coin_source, coin_salt)
            .unwrap()
            .0;
    assert_eq!(
        coin_commitment.digest(),
        independent_secret_leaf_digest(
            COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN,
            vec![
                CanonicalItem::hash512(coin_coordinate.parameter_identity().into_bytes()),
                CanonicalItem::hash512(coin_coordinate.preparation_context_identity().into_bytes(),),
                CanonicalItem::unsigned16(0),
                CanonicalItem::hash512(coin_coordinate.seed_catalog_identity().into_bytes()),
                CanonicalItem::unsigned16(coin_coordinate.participant_count()),
                CanonicalItem::unsigned16(coin_coordinate.contributor_position()),
            ],
            &coin_salt,
            &coin_source,
        )
    );
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_SECRET_LEAF_DOMAIN,
        COLLECTIVE_COIN_SOURCE_SECRET_LEAF_DOMAIN
    );
}

#[test]
fn every_pair_and_coin_coordinate_or_secret_change_changes_the_digest() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let context = preparation_context(participant_count, 0x71);
    let alternate_context = preparation_context(participant_count, 0x73);
    let parameter_identity = deterministic_hash(0x75, 0);
    let pair_contribution = [0x77; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH];
    let salt = [0x79; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH];
    let baseline_pair = pair_digest(parameter_identity, context, 1, 8, pair_contribution, salt);
    for variant in [
        pair_digest(
            deterministic_hash(0x7b, 0),
            context,
            1,
            8,
            pair_contribution,
            salt,
        ),
        pair_digest(
            parameter_identity,
            alternate_context,
            1,
            8,
            pair_contribution,
            salt,
        ),
        pair_digest(parameter_identity, context, 2, 8, pair_contribution, salt),
        pair_digest(parameter_identity, context, 1, 7, pair_contribution, salt),
        pair_digest(
            parameter_identity,
            context,
            1,
            8,
            changed_first_byte(pair_contribution),
            salt,
        ),
        pair_digest(
            parameter_identity,
            context,
            1,
            8,
            pair_contribution,
            changed_first_byte(salt),
        ),
    ] {
        assert_ne!(variant, baseline_pair);
    }

    let coin_source = [0x7d; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH];
    let baseline_coin = coin_digest(parameter_identity, context, 3, coin_source, salt);
    for variant in [
        coin_digest(deterministic_hash(0x7f, 0), context, 3, coin_source, salt),
        coin_digest(parameter_identity, alternate_context, 3, coin_source, salt),
        coin_digest(parameter_identity, context, 4, coin_source, salt),
        coin_digest(
            parameter_identity,
            context,
            3,
            changed_first_byte(coin_source),
            salt,
        ),
        coin_digest(
            parameter_identity,
            context,
            3,
            coin_source,
            changed_first_byte(salt),
        ),
    ] {
        assert_ne!(variant, baseline_coin);
    }
}

#[test]
fn positive_match_refuses_wrong_coordinates_digests_salts_and_secrets() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0x81);
    let parameter_identity = deterministic_hash(0x83, 0);
    let pair_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 0)
            .unwrap();
    let pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            pair_layout,
            6,
        )
        .unwrap();
    let alternate_pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            pair_layout,
            7,
        )
        .unwrap();
    let (pair_commitment, pair_opening) =
        create_pseudorandom_zero_sharing_pair_seed_contribution_320(
            pair_coordinate,
            [0x85; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
            [0x87; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        )
        .unwrap();
    let pair_commitment_bytes = pair_commitment.canonical_bytes().unwrap();
    let pair_opening_bytes = pair_opening.canonical_bytes().unwrap();
    assert_eq!(
        verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
            alternate_pair_coordinate,
            &pair_commitment_bytes,
            &pair_opening_bytes,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::PairCoordinateMismatch
    );
    let changed_pair_commitment = mutate_tuple_item(
        &pair_commitment_bytes,
        9,
        CanonicalItem::hash512([0x89; Hash512::BYTE_LENGTH]),
    );
    assert_eq!(
        verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
            pair_coordinate,
            &changed_pair_commitment,
            &pair_opening_bytes,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::PairCommitmentMismatch
    );
    for (item_position, changed_item) in [
        (
            9,
            CanonicalItem::fixed_bytes(
                [0x8b; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
            )
            .unwrap(),
        ),
        (
            10,
            CanonicalItem::fixed_bytes(
                [0x8d; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
            )
            .unwrap(),
        ),
    ] {
        assert_eq!(
            verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
                pair_coordinate,
                &pair_commitment_bytes,
                &mutate_tuple_item(&pair_opening_bytes, item_position, changed_item),
            )
            .unwrap_err(),
            SeedCatalogSecretLeafError320::PairCommitmentMismatch
        );
    }

    let coin_coordinate =
        CollectiveCoinSourceCoordinate320::from_catalog_layout(pair_layout).unwrap();
    let alternate_coin_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 1)
            .unwrap();
    let alternate_coin_coordinate =
        CollectiveCoinSourceCoordinate320::from_catalog_layout(alternate_coin_layout).unwrap();
    let (coin_commitment, coin_opening) = create_collective_coin_source_320(
        coin_coordinate,
        [0x8f; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        [0x91; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let coin_commitment_bytes = coin_commitment.canonical_bytes().unwrap();
    let coin_opening_bytes = coin_opening.canonical_bytes().unwrap();
    assert_eq!(
        verify_collective_coin_source_320(
            alternate_coin_coordinate,
            &coin_commitment_bytes,
            &coin_opening_bytes,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::CollectiveCoinCoordinateMismatch
    );
    let changed_coin_commitment = mutate_tuple_item(
        &coin_commitment_bytes,
        7,
        CanonicalItem::hash512([0x93; Hash512::BYTE_LENGTH]),
    );
    assert_eq!(
        verify_collective_coin_source_320(
            coin_coordinate,
            &changed_coin_commitment,
            &coin_opening_bytes,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::CollectiveCoinCommitmentMismatch
    );
    for (item_position, changed_item) in [
        (
            7,
            CanonicalItem::fixed_bytes(
                [0x95; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
            )
            .unwrap(),
        ),
        (
            8,
            CanonicalItem::fixed_bytes([0x97; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH]).unwrap(),
        ),
    ] {
        assert_eq!(
            verify_collective_coin_source_320(
                coin_coordinate,
                &coin_commitment_bytes,
                &mutate_tuple_item(&coin_opening_bytes, item_position, changed_item),
            )
            .unwrap_err(),
            SeedCatalogSecretLeafError320::CollectiveCoinCommitmentMismatch
        );
    }
}

#[test]
fn pair_master_requires_exact_lower_then_upper_inventory_and_matches_xor() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0xa1);
    let parameter_identity = deterministic_hash(0xa3, 0);
    let lower_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 2)
            .unwrap();
    let upper_layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 7)
            .unwrap();
    let lower_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            lower_layout,
            7,
        )
        .unwrap();
    let upper_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            upper_layout,
            2,
        )
        .unwrap();
    assert_eq!(lower_coordinate.scope(), upper_coordinate.scope());
    assert_ne!(
        lower_coordinate.seed_catalog_identity(),
        upper_coordinate.seed_catalog_identity()
    );
    let lower_contribution = [0xa5; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH];
    let upper_contribution = deterministic_bytes::<
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
    >(0xa7, 2, 7);
    let expected_master = core::array::from_fn(|byte_position| {
        lower_contribution[byte_position] ^ upper_contribution[byte_position]
    });
    let master = combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320(
        lower_coordinate.scope(),
        vec![
            matched_pair_contribution(lower_coordinate, lower_contribution, 0xa9),
            matched_pair_contribution(upper_coordinate, upper_contribution, 0xab),
        ],
    )
    .unwrap();
    assert_eq!(master.scope(), lower_coordinate.scope());
    assert_eq!(master.as_bytes(), &expected_master);

    let missing = vec![matched_pair_contribution(
        lower_coordinate,
        lower_contribution,
        0xad,
    )];
    assert_eq!(
        combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320(
            lower_coordinate.scope(),
            missing,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::PairContributionCountMismatch {
            expected: 2,
            actual: 1,
        }
    );
    let reversed = vec![
        matched_pair_contribution(upper_coordinate, upper_contribution, 0xaf),
        matched_pair_contribution(lower_coordinate, lower_contribution, 0xb1),
    ];
    assert!(matches!(
        combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320(
            lower_coordinate.scope(),
            reversed,
        ),
        Err(
            SeedCatalogSecretLeafError320::PairContributorOrderMismatch {
                contribution_index: 0,
                expected_contributor_position: 2,
                actual_contributor_position: 7,
            }
        )
    ));
    let duplicate = vec![
        matched_pair_contribution(lower_coordinate, lower_contribution, 0xb3),
        matched_pair_contribution(lower_coordinate, upper_contribution, 0xb5),
    ];
    assert!(matches!(
        combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320(
            lower_coordinate.scope(),
            duplicate,
        ),
        Err(
            SeedCatalogSecretLeafError320::PairContributorOrderMismatch {
                contribution_index: 1,
                expected_contributor_position: 7,
                actual_contributor_position: 2,
            }
        )
    ));

    let alternate_context = preparation_context(FOUNDATION_PROFILE.participant_count, 0xb7);
    let alternate_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        alternate_context,
        7,
    )
    .unwrap();
    let alternate_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            alternate_layout,
            2,
        )
        .unwrap();
    let wrong_scope = vec![
        matched_pair_contribution(lower_coordinate, lower_contribution, 0xb9),
        matched_pair_contribution(alternate_coordinate, upper_contribution, 0xbb),
    ];
    assert_eq!(
        combine_commitment_matched_pseudorandom_zero_sharing_pair_master_320(
            lower_coordinate.scope(),
            wrong_scope,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::PairCoordinateMismatch
    );
}

#[test]
fn pair_and_coin_catalog_adapters_bind_exact_coordinates_digests_and_paths() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0xc1);
    let parameter_identity = deterministic_hash(0xc3, 0);
    let layout =
        PseudorandomZeroSharingSeedCatalogLayout320::derive(parameter_identity, context, 4)
            .unwrap();
    let pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(layout, 8)
            .unwrap();
    let (pair_commitment, pair_opening) =
        create_pseudorandom_zero_sharing_pair_seed_contribution_320(
            pair_coordinate,
            [0xc5; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
            [0xc7; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        )
        .unwrap();
    let coin_coordinate = CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
    let (coin_commitment, coin_opening) = create_collective_coin_source_320(
        coin_coordinate,
        [0xc9; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        [0xcb; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let pair_leaf_ordinal = layout
        .leaf_ordinal(layout.pair_coordinate(8).unwrap())
        .unwrap();
    let coin_leaf_ordinal = layout
        .leaf_ordinal(layout.collective_coin_coordinate())
        .unwrap();
    let mut commitment_digests = (0..layout.leaf_count())
        .map(|leaf_ordinal| deterministic_hash(0xcd, leaf_ordinal as u16))
        .collect::<Vec<_>>();
    commitment_digests[pair_leaf_ordinal as usize] = pair_commitment.digest();
    commitment_digests[coin_leaf_ordinal as usize] = coin_commitment.digest();
    let tree =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests).unwrap();
    let root_body_bytes = tree.root_body().canonical_bytes().unwrap();
    let pair_proof_bytes = tree
        .inclusion_proof(pair_leaf_ordinal)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let coin_proof_bytes = tree
        .inclusion_proof(coin_leaf_ordinal)
        .unwrap()
        .canonical_bytes()
        .unwrap();

    let (included_pair, matched_pair) =
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
            layout,
            8,
            &root_body_bytes,
            &pair_opening.canonical_bytes().unwrap(),
            &pair_proof_bytes,
        )
        .unwrap();
    assert_eq!(
        included_pair.coordinate(),
        layout.pair_coordinate(8).unwrap()
    );
    assert_eq!(included_pair.commitment_digest(), pair_commitment.digest());
    assert_eq!(matched_pair.coordinate(), pair_coordinate);
    let (included_coin, matched_coin) =
        verify_collective_coin_source_opening_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            &coin_opening.canonical_bytes().unwrap(),
            &coin_proof_bytes,
        )
        .unwrap();
    assert_eq!(
        included_coin.coordinate(),
        layout.collective_coin_coordinate()
    );
    assert_eq!(included_coin.commitment_digest(), coin_commitment.digest());
    assert_eq!(matched_coin.coordinate(), coin_coordinate);
    assert_eq!(
        included_pair.root_body_identity(),
        included_coin.root_body_identity()
    );

    assert_eq!(
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
            layout,
            7,
            &root_body_bytes,
            &pair_opening.canonical_bytes().unwrap(),
            &pair_proof_bytes,
        )
        .unwrap_err(),
        SeedCatalogSecretLeafError320::PairCoordinateMismatch
    );
    assert!(
        verify_pseudorandom_zero_sharing_pair_seed_opening_catalog_inclusion_320(
            layout,
            8,
            &root_body_bytes,
            &mutate_tuple_item(
                &pair_opening.canonical_bytes().unwrap(),
                10,
                CanonicalItem::fixed_bytes(
                    [0xcf; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
                )
                .unwrap(),
            ),
            &pair_proof_bytes,
        )
        .is_err()
    );
    assert!(
        verify_collective_coin_source_opening_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            &coin_opening.canonical_bytes().unwrap(),
            &pair_proof_bytes,
        )
        .is_err()
    );
}

#[test]
fn decoders_refuse_malformed_cross_domain_truncated_and_oversized_objects() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0xd1);
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        deterministic_hash(0xd3, 0),
        context,
        3,
    )
    .unwrap();
    let pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(layout, 6)
            .unwrap();
    let (pair_commitment, pair_opening) =
        create_pseudorandom_zero_sharing_pair_seed_contribution_320(
            pair_coordinate,
            [0xd5; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
            [0xd7; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        )
        .unwrap();
    let pair_commitment_bytes = pair_commitment.canonical_bytes().unwrap();
    let pair_opening_bytes = pair_opening.canonical_bytes().unwrap();
    let coin_coordinate = CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
    let (coin_commitment, coin_opening) = create_collective_coin_source_320(
        coin_coordinate,
        [0xd9; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        [0xdb; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let coin_commitment_bytes = coin_commitment.canonical_bytes().unwrap();
    let coin_opening_bytes = coin_opening.canonical_bytes().unwrap();

    let mut wrong_schema = decode_tuple(&pair_commitment_bytes);
    wrong_schema.schema_identifier = CANONICAL_TUPLE_SCHEMA_IDENTIFIER + 1;
    assert_object_mismatch(
        PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(
            &wrong_schema.encode().unwrap(),
        ),
        "schema identifier",
    );
    let mut wrong_version = decode_tuple(&coin_commitment_bytes);
    wrong_version.schema_version = CANONICAL_TUPLE_VERSION + 1;
    assert_object_mismatch(
        CollectiveCoinSourceCommitment320::from_canonical_bytes(&wrong_version.encode().unwrap()),
        "schema version",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &pair_commitment_bytes,
            0,
            CanonicalItem::nonempty_ascii(
                PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_DOMAIN,
            )
            .unwrap(),
        )),
        "object domain",
    );
    assert_object_mismatch(
        CollectiveCoinSourceOpening320::from_canonical_bytes(&mutate_tuple_item(
            &coin_opening_bytes,
            0,
            CanonicalItem::nonempty_ascii(COLLECTIVE_COIN_SOURCE_COMMITMENT_OBJECT_DOMAIN).unwrap(),
        )),
        "object domain",
    );
    let mut missing_item = decode_tuple(&pair_opening_bytes);
    missing_item.items.pop();
    assert_object_mismatch(
        PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(
            &missing_item.encode().unwrap(),
        ),
        "item count",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &pair_commitment_bytes,
            7,
            CanonicalItem::unsigned16(3),
        )),
        "pair endpoints",
    );
    assert_object_mismatch(
        CollectiveCoinSourceCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &coin_commitment_bytes,
            6,
            CanonicalItem::unsigned16(FOUNDATION_PROFILE.participant_count),
        )),
        "contributor position",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(&mutate_tuple_item(
            &pair_opening_bytes,
            9,
            CanonicalItem::fixed_bytes(
                [0; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH - 1],
            )
            .unwrap(),
        )),
        "commitment salt",
    );
    assert_object_mismatch(
        CollectiveCoinSourceOpening320::from_canonical_bytes(&mutate_tuple_item(
            &coin_opening_bytes,
            8,
            CanonicalItem::fixed_bytes([0; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH - 1]).unwrap(),
        )),
        "coin source",
    );

    for prefix_length in 0..pair_commitment_bytes.len() {
        assert!(
            PseudorandomZeroSharingPairSeedCommitment320::from_canonical_bytes(
                &pair_commitment_bytes[..prefix_length]
            )
            .is_err()
        );
    }
    for prefix_length in 0..pair_opening_bytes.len() {
        assert!(
            PseudorandomZeroSharingPairSeedOpening320::from_canonical_bytes(
                &pair_opening_bytes[..prefix_length]
            )
            .is_err()
        );
    }
    for prefix_length in 0..coin_commitment_bytes.len() {
        assert!(
            CollectiveCoinSourceCommitment320::from_canonical_bytes(
                &coin_commitment_bytes[..prefix_length]
            )
            .is_err()
        );
    }
    for prefix_length in 0..coin_opening_bytes.len() {
        assert!(
            CollectiveCoinSourceOpening320::from_canonical_bytes(
                &coin_opening_bytes[..prefix_length]
            )
            .is_err()
        );
    }
    let oversized = vec![0; 1_025];
    assert!(matches!(
        CollectiveCoinSourceOpening320::from_canonical_bytes(&oversized),
        Err(SeedCatalogSecretLeafError320::Canonical(_))
    ));
}

#[test]
fn zero_secret_values_are_valid_and_debug_output_redacts_them() {
    let context = preparation_context(FOUNDATION_PROFILE.participant_count, 0xe1);
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        deterministic_hash(0xe3, 0),
        context,
        0,
    )
    .unwrap();
    let pair_coordinate =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(layout, 1)
            .unwrap();
    let (pair_commitment, pair_opening) =
        create_pseudorandom_zero_sharing_pair_seed_contribution_320(
            pair_coordinate,
            [0; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
            [0; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
        )
        .unwrap();
    let matched_pair = verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
        pair_coordinate,
        &pair_commitment.canonical_bytes().unwrap(),
        &pair_opening.canonical_bytes().unwrap(),
    )
    .unwrap();
    assert!(format!("{pair_opening:?}").contains("[redacted]"));
    assert!(format!("{matched_pair:?}").contains("[redacted]"));

    let coin_coordinate = CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
    let (coin_commitment, coin_opening) = create_collective_coin_source_320(
        coin_coordinate,
        [0; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
        [0; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let matched_coin = verify_collective_coin_source_320(
        coin_coordinate,
        &coin_commitment.canonical_bytes().unwrap(),
        &coin_opening.canonical_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(
        matched_coin.as_bytes(),
        &[0; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH]
    );
    assert!(format!("{coin_opening:?}").contains("[redacted]"));
    assert!(format!("{matched_coin:?}").contains("[redacted]"));
}

fn matched_pair_contribution(
    coordinate: PseudorandomZeroSharingPairSeedContributionCoordinate320,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
    salt_marker: u8,
) -> super::pseudorandom_zero_sharing_pair_and_coin_seed_320::CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320
{
    let (commitment, opening) = create_pseudorandom_zero_sharing_pair_seed_contribution_320(
        coordinate,
        contribution,
        [salt_marker; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
        coordinate,
        &commitment.canonical_bytes().unwrap(),
        &opening.canonical_bytes().unwrap(),
    )
    .unwrap()
}

fn pair_digest(
    parameter_identity: Hash512,
    context: TallyPreparationContext,
    contributor_position: u16,
    counterpart_position: u16,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
    salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
) -> Hash512 {
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        context,
        contributor_position,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
        layout,
        counterpart_position,
    )
    .unwrap();
    create_pseudorandom_zero_sharing_pair_seed_contribution_320(coordinate, contribution, salt)
        .unwrap()
        .0
        .digest()
}

fn coin_digest(
    parameter_identity: Hash512,
    context: TallyPreparationContext,
    contributor_position: u16,
    source: [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH],
    salt: [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
) -> Hash512 {
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        context,
        contributor_position,
    )
    .unwrap();
    let coordinate = CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
    create_collective_coin_source_320(coordinate, source, salt)
        .unwrap()
        .0
        .digest()
}

fn independent_secret_leaf_digest<const SECRET_BYTE_LENGTH: usize>(
    domain: &str,
    mut prefix_items: Vec<CanonicalItem>,
    salt: &[u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    secret: &[u8; SECRET_BYTE_LENGTH],
) -> Hash512 {
    let mut payload = Vec::with_capacity(salt.len() + secret.len());
    payload.extend_from_slice(salt);
    payload.extend_from_slice(secret);
    let mut items = Vec::with_capacity(prefix_items.len() + 2);
    items.push(CanonicalItem::nonempty_ascii(domain).unwrap());
    items.append(&mut prefix_items);
    items.push(CanonicalItem::variable_bytes(&payload).unwrap());
    let preimage = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        items,
    )
    .encode()
    .unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&preimage);
    let mut digest = [0; Hash512::BYTE_LENGTH];
    hasher.finalize_xof().read(&mut digest);
    Hash512::from_bytes(digest)
}

fn deterministic_bytes<const BYTE_LENGTH: usize>(
    marker: u8,
    first_position: u16,
    second_position: u16,
) -> [u8; BYTE_LENGTH] {
    core::array::from_fn(|byte_position| {
        marker
            .wrapping_add((first_position as u8).wrapping_mul(17))
            .wrapping_add((second_position as u8).wrapping_mul(29))
            .wrapping_add((byte_position as u8).wrapping_mul(31))
    })
}

fn deterministic_hash(marker: u8, ordinal: u16) -> Hash512 {
    Hash512::from_bytes(deterministic_bytes::<{ Hash512::BYTE_LENGTH }>(
        marker, ordinal, 0,
    ))
}

fn changed_first_byte<const BYTE_LENGTH: usize>(mut bytes: [u8; BYTE_LENGTH]) -> [u8; BYTE_LENGTH] {
    bytes[0] ^= 1;
    bytes
}

fn mutate_tuple_item(bytes: &[u8], item_position: usize, item: CanonicalItem) -> Vec<u8> {
    let mut tuple = decode_tuple(bytes);
    tuple.items[item_position] = item;
    tuple.encode().unwrap()
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}

fn assert_object_mismatch<T: core::fmt::Debug>(
    result: Result<T, SeedCatalogSecretLeafError320>,
    expected_field: &'static str,
) {
    assert!(matches!(
        result,
        Err(SeedCatalogSecretLeafError320::ObjectMismatch { field, .. })
            if field == expected_field
    ));
}

fn preparation_context(participant_count: u16, marker: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        deterministic_hash(marker, 1),
        deterministic_hash(marker, 2),
        [marker; 32],
        &circuit,
    )
    .unwrap()
}
