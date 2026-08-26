use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
        CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        derive_foundation_roster_parameters, hash_foundation_tuple_512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_seed_catalog_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_IDENTITY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INTERNAL_NODE_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_PADDING_LEAF_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_IDENTITY_DOMAIN,
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
        PseudorandomZeroSharingSeedCatalogTree320, compiler_identity_from_source_for_test,
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320,
        verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingSubsetSeedCoordinate320, PseudorandomZeroSharingSubsetSeedScope320,
        create_pseudorandom_zero_sharing_subset_seed_contribution_320,
    },
};

#[test]
fn every_admitted_roster_and_contributor_has_a_formula_derived_bijective_catalog() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let context = context(participant_count, participant_count as u8);
        let parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let expected_subset_count = independent_binomial(
            u64::from(participant_count - 1),
            u64::from(parameters.active_fault_bound),
        );
        let expected_pair_count = u64::from(participant_count - 1);
        let expected_leaf_count = expected_subset_count + expected_pair_count + 1;
        let expected_capacity = expected_leaf_count.next_power_of_two();

        for contributor_position in 0..participant_count {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                Hash512::from_bytes([0x31; 64]),
                context,
                contributor_position,
            )
            .unwrap();
            assert_eq!(layout.subset_leaf_count(), expected_subset_count);
            assert_eq!(layout.pair_leaf_count(), expected_pair_count);
            assert_eq!(layout.collective_coin_leaf_count(), 1);
            assert_eq!(layout.leaf_count(), expected_leaf_count);
            assert_eq!(layout.tree_capacity(), expected_capacity);
            assert_eq!(layout.tree_height(), expected_capacity.ilog2() as u16);

            let coordinates = layout.coordinates().unwrap().collect::<Vec<_>>();
            assert_eq!(coordinates.len(), expected_leaf_count as usize);
            for (expected_ordinal, coordinate) in coordinates.iter().copied().enumerate() {
                let expected_ordinal = expected_ordinal as u64;
                assert_eq!(layout.leaf_ordinal(coordinate).unwrap(), expected_ordinal);
            }
            let sampled_ordinals = [
                0,
                expected_subset_count.saturating_sub(1),
                expected_subset_count,
                expected_leaf_count.saturating_sub(2),
                expected_leaf_count - 1,
            ];
            for sampled_ordinal in sampled_ordinals {
                assert_eq!(
                    layout.coordinate(sampled_ordinal).unwrap(),
                    coordinates[sampled_ordinal as usize]
                );
            }
            assert!(matches!(
                coordinates.last(),
                Some(PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin)
            ));
            assert_eq!(
                layout
                    .leaf_ordinal(layout.collective_coin_coordinate())
                    .unwrap(),
                expected_leaf_count - 1
            );
            assert_eq!(
                layout.coordinate(expected_leaf_count),
                Err(
                    TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafOrdinalOutOfRange {
                        leaf_ordinal: expected_leaf_count,
                        leaf_count: expected_leaf_count,
                    }
                )
            );
        }
    }
}

#[test]
fn completion_catalog_has_ninety_four_leaves_and_every_proof_roundtrips() {
    let layout = completion_layout(4, 0x41);
    assert_eq!(layout.subset_leaf_count(), 84);
    assert_eq!(layout.pair_leaf_count(), 9);
    assert_eq!(layout.leaf_count(), 94);
    assert_eq!(layout.tree_capacity(), 128);
    assert_eq!(layout.tree_height(), 7);

    let commitment_digests = deterministic_commitment_digests(layout.leaf_count(), 0x52);
    let tree =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests.clone())
            .unwrap();
    let root_body_bytes = tree.root_body().canonical_bytes().unwrap();
    let expected_root_body_byte_length = 8
        + 15 * 6
        + 4
        + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN.len()
        + 5 * Hash512::BYTE_LENGTH
        + 4 * 2
        + 5 * 8;
    assert_eq!(root_body_bytes.len(), expected_root_body_byte_length);
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
            layout,
            &root_body_bytes,
        )
        .unwrap(),
        tree.root_body()
    );
    assert_eq!(
        tree.root_body().identity().unwrap(),
        hash_foundation_tuple_512(
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(&root_body_bytes).unwrap()],
        )
        .unwrap()
    );
    assert_eq!(
        tree.root_body().root_digest(),
        independent_catalog_root(layout, &commitment_digests)
    );

    for (leaf_ordinal, (coordinate, commitment_digest)) in layout
        .coordinates()
        .unwrap()
        .zip(commitment_digests)
        .enumerate()
    {
        let leaf_ordinal = leaf_ordinal as u64;
        let proof_bytes = tree
            .inclusion_proof(leaf_ordinal)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let expected_proof_byte_length = 8
            + (4 + usize::from(layout.tree_height())) * 6
            + 4
            + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN.len()
            + Hash512::BYTE_LENGTH
            + 8
            + 2
            + usize::from(layout.tree_height()) * Hash512::BYTE_LENGTH;
        assert_eq!(proof_bytes.len(), expected_proof_byte_length);
        let included = verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            coordinate,
            commitment_digest,
            &proof_bytes,
        )
        .unwrap();
        assert_eq!(included.coordinate(), coordinate);
        assert_eq!(included.commitment_digest(), commitment_digest);
        assert_eq!(
            included.root_body_identity(),
            tree.root_body().identity().unwrap()
        );
    }
}

#[test]
fn subset_opening_adapter_binds_the_catalog_identity_coordinate_digest_and_path() {
    let layout = completion_layout(2, 0x61);
    let subset = layout
        .coordinates()
        .unwrap()
        .find_map(|coordinate| match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => Some(subset),
            _ => None,
        })
        .unwrap();
    let subset_seed_coordinate = layout.subset_seed_coordinate(subset).unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        subset_seed_coordinate,
        [0x73; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [0x79; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let leaf_ordinal = layout
        .leaf_ordinal(layout.subset_coordinate(subset).unwrap())
        .unwrap();
    let mut commitment_digests = deterministic_commitment_digests(layout.leaf_count(), 0x71);
    commitment_digests[leaf_ordinal as usize] = commitment.digest();
    let tree =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests).unwrap();
    let root_body_bytes = tree.root_body().canonical_bytes().unwrap();
    let proof_bytes = tree
        .inclusion_proof(leaf_ordinal)
        .unwrap()
        .canonical_bytes()
        .unwrap();

    let (included, _) = verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320(
        layout,
        subset,
        &root_body_bytes,
        &opening.canonical_bytes().unwrap(),
        &proof_bytes,
    )
    .unwrap();
    assert_eq!(included.commitment_digest(), commitment.digest());

    let other_layout = completion_layout(2, 0x62);
    let wrong_scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        other_layout.parameter_identity(),
        other_layout.preparation_context(),
        other_layout.identity(),
        subset,
    )
    .unwrap();
    let wrong_coordinate =
        PseudorandomZeroSharingSubsetSeedCoordinate320::new(wrong_scope, 2).unwrap();
    let (_, wrong_opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        wrong_coordinate,
        [0x73; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [0x79; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_subset_seed_opening_catalog_inclusion_320(
            layout,
            subset,
            &root_body_bytes,
            &wrong_opening.canonical_bytes().unwrap(),
            &proof_bytes,
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch)
    ));
}

#[test]
fn inclusion_refuses_wrong_roots_digests_coordinates_paths_and_malformed_objects() {
    let layout = completion_layout(5, 0x81);
    let commitment_digests = deterministic_commitment_digests(layout.leaf_count(), 0x83);
    let tree =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests.clone())
            .unwrap();
    let root_body_bytes = tree.root_body().canonical_bytes().unwrap();
    let coordinate = layout.coordinate(0).unwrap();
    let proof_bytes = tree.inclusion_proof(0).unwrap().canonical_bytes().unwrap();

    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            coordinate,
            changed_hash(commitment_digests[0]),
            &proof_bytes,
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch)
    );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            layout.coordinate(1).unwrap(),
            commitment_digests[0],
            &proof_bytes,
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogObjectMismatch {
                field: "leaf ordinal"
            }
        )
    ));

    let mut changed_proof_tuple = decode_tuple(&proof_bytes);
    let sibling_item_position = 4;
    let sibling_digest = Hash512::from_bytes(
        changed_proof_tuple.items[sibling_item_position]
            .canonical_bytes()
            .try_into()
            .unwrap(),
    );
    changed_proof_tuple.items[sibling_item_position] =
        CanonicalItem::hash512(changed_hash(sibling_digest).into_bytes());
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            coordinate,
            commitment_digests[0],
            &changed_proof_tuple.encode().unwrap(),
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch)
    );

    let mut short_proof_tuple = decode_tuple(&proof_bytes);
    short_proof_tuple.items.pop();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &root_body_bytes,
            coordinate,
            commitment_digests[0],
            &short_proof_tuple.encode().unwrap(),
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogObjectMismatch {
                field: "item count"
            }
        )
    ));

    let mut changed_root_tuple = decode_tuple(&root_body_bytes);
    changed_root_tuple.items[14] =
        CanonicalItem::hash512(changed_hash(tree.root_body().root_digest()).into_bytes());
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
            layout,
            &changed_root_tuple.encode().unwrap(),
            coordinate,
            commitment_digests[0],
            &proof_bytes,
        ),
        Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch)
    );

    let mut wrong_context_tuple = decode_tuple(&root_body_bytes);
    wrong_context_tuple.items[2] = CanonicalItem::hash512([0xa1; 64]);
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
            layout,
            &wrong_context_tuple.encode().unwrap(),
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogObjectMismatch {
                field: "preparation context identity"
            }
        )
    ));

    for truncated_length in 0..root_body_bytes.len() {
        assert!(
            PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
                layout,
                &root_body_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    for truncated_length in 0..proof_bytes.len() {
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_inclusion_320(
                layout,
                &root_body_bytes,
                coordinate,
                commitment_digests[0],
                &proof_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    assert!(
        PseudorandomZeroSharingSeedCatalogRootBody320::from_canonical_bytes(
            layout,
            &[0_u8; 4_097],
        )
        .is_err()
    );
}

#[test]
fn catalog_identity_and_root_change_with_every_owner_scope_and_leaf_order() {
    let layout = completion_layout(0, 0x91);
    let changed_parameter_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0x92; 64]),
        layout.preparation_context(),
        0,
    )
    .unwrap();
    let changed_context_layout = completion_layout(0, 0x93);
    let changed_contributor_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        layout.parameter_identity(),
        layout.preparation_context(),
        1,
    )
    .unwrap();
    assert_ne!(layout.identity(), changed_parameter_layout.identity());
    assert_ne!(layout.identity(), changed_context_layout.identity());
    assert_ne!(layout.identity(), changed_contributor_layout.identity());
    assert_eq!(
        layout.compiler_identity(),
        changed_context_layout.compiler_identity()
    );

    let commitment_digests = deterministic_commitment_digests(layout.leaf_count(), 0x95);
    let original_root =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests.clone())
            .unwrap()
            .root_body()
            .root_digest();
    let mut reversed_commitment_digests = commitment_digests;
    reversed_commitment_digests.reverse();
    let reversed_root =
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, reversed_commitment_digests)
            .unwrap()
            .root_body()
            .root_digest();
    assert_ne!(original_root, reversed_root);

    let independently_derived_identity = hash_foundation_tuple_512(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_IDENTITY_DOMAIN,
        &[
            CanonicalItem::hash512(layout.parameter_identity().into_bytes()),
            CanonicalItem::hash512(layout.preparation_context().identity().into_bytes()),
            CanonicalItem::unsigned16(0),
            CanonicalItem::hash512(layout.compiler_identity().into_bytes()),
            CanonicalItem::unsigned16(layout.participant_count()),
            CanonicalItem::unsigned16(layout.contributor_position()),
            CanonicalItem::unsigned64(layout.subset_leaf_count()),
            CanonicalItem::unsigned64(layout.pair_leaf_count()),
            CanonicalItem::unsigned64(layout.collective_coin_leaf_count()),
            CanonicalItem::unsigned64(layout.leaf_count()),
            CanonicalItem::unsigned64(layout.tree_capacity()),
            CanonicalItem::unsigned16(layout.tree_height()),
        ],
    )
    .unwrap();
    assert_eq!(layout.identity(), independently_derived_identity);
}

#[test]
fn construction_refuses_incomplete_catalogs_invalid_coordinates_and_noncanonical_source() {
    let layout = completion_layout(3, 0xb1);
    let mut missing_leaf = deterministic_commitment_digests(layout.leaf_count(), 0xb3);
    missing_leaf.pop();
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, missing_leaf),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafCountMismatch {
                expected: 94,
                actual: 93,
            }
        )
    ));
    let mut extra_leaf = deterministic_commitment_digests(layout.leaf_count(), 0xb5);
    extra_leaf.push(Hash512::from_bytes([0xb7; 64]));
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogTree320::create(layout, extra_leaf),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogLeafCountMismatch {
                expected: 94,
                actual: 95,
            }
        )
    ));
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogLayout320::derive(
            Hash512::from_bytes([0xb9; 64]),
            layout.preparation_context(),
            layout.participant_count(),
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSeedCatalogContributorPositionOutOfRange {
                contributor_position: layout.participant_count(),
                participant_count: layout.participant_count(),
            }
        )
    );
    assert_eq!(
        layout.pair_coordinate(layout.contributor_position()),
        Err(TallyPreparationError::PseudorandomZeroSharingSeedCatalogCoordinateMismatch)
    );
    assert!(compiler_identity_from_source_for_test(b"canonical source\n").is_ok());
    for malformed_source in [
        b"missing final newline".as_slice(),
        b"carriage\rreturn\n".as_slice(),
        b"\xef\xbb\xbfbyte order mark\n".as_slice(),
        &[0xff, b'\n'],
    ] {
        assert_eq!(
            compiler_identity_from_source_for_test(malformed_source),
            Err(TallyPreparationError::NonCanonicalPreparationSourceEncoding)
        );
    }
}

fn completion_layout(
    contributor_position: u16,
    attempt_marker: u8,
) -> PseudorandomZeroSharingSeedCatalogLayout320 {
    PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0x2b; 64]),
        context(FOUNDATION_PROFILE.participant_count, attempt_marker),
        contributor_position,
    )
    .unwrap()
}

fn context(participant_count: u16, attempt_marker: u8) -> TallyPreparationContext {
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(participant_count, 2, 2).unwrap())
            .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([0xc1; 64]),
        Hash512::from_bytes([0xc3; 64]),
        [attempt_marker; 32],
        &circuit,
    )
    .unwrap()
}

fn deterministic_commitment_digests(leaf_count: u64, marker: u8) -> Vec<Hash512> {
    (0..leaf_count)
        .map(|leaf_ordinal| {
            let mut bytes = [marker; Hash512::BYTE_LENGTH];
            bytes[..8].copy_from_slice(&leaf_ordinal.to_le_bytes());
            Hash512::from_bytes(bytes)
        })
        .collect()
}

fn independent_catalog_root(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    commitment_digests: &[Hash512],
) -> Hash512 {
    let mut layer = layout
        .coordinates()
        .unwrap()
        .zip(commitment_digests.iter().copied())
        .enumerate()
        .map(|(leaf_ordinal, (coordinate, commitment_digest))| {
            independent_leaf_digest(layout, leaf_ordinal as u64, coordinate, commitment_digest)
        })
        .collect::<Vec<_>>();
    for padding_ordinal in layout.leaf_count()..layout.tree_capacity() {
        layer.push(
            hash_foundation_tuple_512(
                PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_PADDING_LEAF_DOMAIN,
                &[
                    CanonicalItem::hash512(layout.identity().into_bytes()),
                    CanonicalItem::unsigned64(padding_ordinal),
                ],
            )
            .unwrap(),
        );
    }
    for level in 0..layout.tree_height() {
        layer = layer
            .chunks_exact(2)
            .enumerate()
            .map(|(node_index, children)| {
                hash_foundation_tuple_512(
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INTERNAL_NODE_DOMAIN,
                    &[
                        CanonicalItem::hash512(layout.identity().into_bytes()),
                        CanonicalItem::unsigned16(level),
                        CanonicalItem::unsigned64(node_index as u64),
                        CanonicalItem::hash512(children[0].into_bytes()),
                        CanonicalItem::hash512(children[1].into_bytes()),
                    ],
                )
                .unwrap()
            })
            .collect();
    }
    assert_eq!(layer.len(), 1);
    layer[0]
}

fn independent_leaf_digest(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    leaf_ordinal: u64,
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
    commitment_digest: Hash512,
) -> Hash512 {
    let mut items = vec![
        CanonicalItem::hash512(layout.identity().into_bytes()),
        CanonicalItem::unsigned64(leaf_ordinal),
        CanonicalItem::unsigned16(layout.participant_count()),
        CanonicalItem::unsigned16(layout.contributor_position()),
    ];
    match coordinate {
        PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
            items.push(CanonicalItem::unsigned8(1));
            items.push(CanonicalItem::unsigned32(subset.excluded_position_mask()));
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
            lower_roster_position,
            upper_roster_position,
        } => {
            items.push(CanonicalItem::unsigned8(2));
            items.push(CanonicalItem::unsigned16(lower_roster_position));
            items.push(CanonicalItem::unsigned16(upper_roster_position));
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
            items.push(CanonicalItem::unsigned8(3));
        }
    }
    items.push(CanonicalItem::hash512(commitment_digest.into_bytes()));
    hash_foundation_tuple_512(PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN, &items).unwrap()
}

fn independent_binomial(population_size: u64, selected_size: u64) -> u64 {
    if selected_size > population_size {
        return 0;
    }
    let selected_size = selected_size.min(population_size - selected_size);
    (1..=selected_size).fold(1_u64, |result, selected_position| {
        result * (population_size - selected_size + selected_position) / selected_position
    })
}

fn changed_hash(hash: Hash512) -> Hash512 {
    let mut bytes = hash.into_bytes();
    bytes[0] ^= 0x80;
    Hash512::from_bytes(bytes)
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}

#[test]
fn root_and_proof_object_domains_are_distinct_and_canonical() {
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INCLUSION_PROOF_DOMAIN
    );
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_INTERNAL_NODE_DOMAIN
    );
    assert_ne!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_LEAF_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_PADDING_LEAF_DOMAIN
    );
    assert_eq!(CANONICAL_TUPLE_SCHEMA_IDENTIFIER, 1);
    assert_eq!(CANONICAL_TUPLE_VERSION, 1);
}
