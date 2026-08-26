use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
        CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_SECRET_LEAF_DOMAIN,
        PseudorandomZeroSharingSubsetSeedCommitment320,
        PseudorandomZeroSharingSubsetSeedCoordinate320,
        PseudorandomZeroSharingSubsetSeedOpening320, PseudorandomZeroSharingSubsetSeedScope320,
        combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320,
        create_pseudorandom_zero_sharing_subset_seed_contribution_320,
        verify_pseudorandom_zero_sharing_subset_seed_contribution_320,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

#[test]
fn every_completion_subset_member_roundtrips_and_combines_to_the_independent_xor() {
    let context = completion_context(11);
    let parameter_identity = Hash512::from_bytes([17_u8; 64]);
    let catalog_identity = Hash512::from_bytes([23_u8; 64]);
    let subsets = ReplicatedRandomSharingSubset::iter(FOUNDATION_PROFILE.participant_count)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(subsets.len(), 120);

    for subset in subsets {
        let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
            parameter_identity,
            context,
            catalog_identity,
            subset,
        )
        .unwrap();
        let mut expected_master =
            [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH];
        let mut matched_contributions = Vec::new();
        for contributor_position in subset.member_positions() {
            let coordinate =
                PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, contributor_position)
                    .unwrap();
            let contribution = deterministic_contribution(subset, contributor_position);
            let commitment_salt = deterministic_salt(subset, contributor_position);
            for (master_byte, contribution_byte) in
                expected_master.iter_mut().zip(contribution.iter())
            {
                *master_byte ^= contribution_byte;
            }
            let (commitment, opening) =
                create_pseudorandom_zero_sharing_subset_seed_contribution_320(
                    coordinate,
                    contribution,
                    commitment_salt,
                )
                .unwrap();
            let commitment_bytes = commitment.canonical_bytes().unwrap();
            let opening_bytes = opening.canonical_bytes().unwrap();
            assert_eq!(
                commitment_bytes.len(),
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_OBJECT_BYTE_LENGTH
            );
            assert_eq!(
                opening_bytes.len(),
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
            );
            assert_eq!(
                PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(
                    &commitment_bytes
                )
                .unwrap(),
                commitment
            );
            assert_eq!(
                PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(&opening_bytes)
                    .unwrap(),
                opening
            );
            matched_contributions.push(
                verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
                    coordinate,
                    &commitment_bytes,
                    &opening_bytes,
                )
                .unwrap(),
            );
        }

        matched_contributions.reverse();
        let master = combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(
            scope,
            matched_contributions,
        )
        .unwrap();
        assert_eq!(master.scope(), scope);
        assert_eq!(master.as_bytes(), &expected_master);
    }
}

#[test]
fn salted_leaf_digest_matches_independent_canonical_shake_framing() {
    let context = completion_context(29);
    let subset = completion_subset(&[1, 4, 8]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([31_u8; 64]),
        context,
        Hash512::from_bytes([37_u8; 64]),
        subset,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 3).unwrap();
    let contribution = deterministic_contribution(subset, 3);
    let commitment_salt = deterministic_salt(subset, 3);
    let (commitment, _) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        contribution,
        commitment_salt,
    )
    .unwrap();

    let mut secret_payload = Vec::with_capacity(
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH
            + PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
    );
    secret_payload.extend_from_slice(&commitment_salt);
    secret_payload.extend_from_slice(&contribution);
    let independently_framed = CanonicalTuple::new(
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER,
        CANONICAL_TUPLE_VERSION,
        vec![
            CanonicalItem::nonempty_ascii(PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_SECRET_LEAF_DOMAIN)
                .unwrap(),
            CanonicalItem::hash512(scope.parameter_identity().into_bytes()),
            CanonicalItem::hash512(scope.preparation_context_identity().into_bytes()),
            CanonicalItem::unsigned16(0),
            CanonicalItem::hash512(scope.seed_catalog_identity().into_bytes()),
            CanonicalItem::unsigned16(subset.participant_count()),
            CanonicalItem::unsigned32(subset.excluded_position_mask()),
            CanonicalItem::unsigned16(3),
            CanonicalItem::variable_bytes(&secret_payload).unwrap(),
        ],
    )
    .encode()
    .unwrap();
    let mut hasher = Shake256::default();
    hasher.update(&independently_framed);
    let mut expected_digest = [0_u8; Hash512::BYTE_LENGTH];
    hasher.finalize_xof().read(&mut expected_digest);

    assert_eq!(commitment.digest(), Hash512::from_bytes(expected_digest));
}

#[test]
fn every_public_coordinate_and_secret_dimension_changes_the_leaf_digest() {
    let context = completion_context(41);
    let alternate_context = completion_context(43);
    let subset = completion_subset(&[2, 5, 9]);
    let alternate_subset = completion_subset(&[2, 6, 9]);
    let parameter_identity = Hash512::from_bytes([47_u8; 64]);
    let catalog_identity = Hash512::from_bytes([53_u8; 64]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        parameter_identity,
        context,
        catalog_identity,
        subset,
    )
    .unwrap();
    let contribution = [59_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH];
    let commitment_salt =
        [61_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH];
    let baseline = commitment_digest(scope, 0, contribution, commitment_salt);

    let variants = [
        commitment_digest(
            PseudorandomZeroSharingSubsetSeedScope320::new(
                Hash512::from_bytes([67_u8; 64]),
                context,
                catalog_identity,
                subset,
            )
            .unwrap(),
            0,
            contribution,
            commitment_salt,
        ),
        commitment_digest(
            PseudorandomZeroSharingSubsetSeedScope320::new(
                parameter_identity,
                alternate_context,
                catalog_identity,
                subset,
            )
            .unwrap(),
            0,
            contribution,
            commitment_salt,
        ),
        commitment_digest(
            PseudorandomZeroSharingSubsetSeedScope320::new(
                parameter_identity,
                context,
                Hash512::from_bytes([71_u8; 64]),
                subset,
            )
            .unwrap(),
            0,
            contribution,
            commitment_salt,
        ),
        commitment_digest(
            PseudorandomZeroSharingSubsetSeedScope320::new(
                parameter_identity,
                context,
                catalog_identity,
                alternate_subset,
            )
            .unwrap(),
            0,
            contribution,
            commitment_salt,
        ),
        commitment_digest(scope, 1, contribution, commitment_salt),
        commitment_digest(scope, 0, changed_first_byte(contribution), commitment_salt),
        commitment_digest(scope, 0, contribution, changed_first_byte(commitment_salt)),
    ];

    for variant in variants {
        assert_ne!(variant, baseline);
    }
}

#[test]
fn positive_match_refuses_wrong_coordinates_digests_salts_and_contributions() {
    let context = completion_context(73);
    let subset = completion_subset(&[3, 6, 9]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([79_u8; 64]),
        context,
        Hash512::from_bytes([83_u8; 64]),
        subset,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 0).unwrap();
    let alternate_coordinate =
        PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 1).unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        [89_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [97_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let commitment_bytes = commitment.canonical_bytes().unwrap();
    let opening_bytes = opening.canonical_bytes().unwrap();

    assert_eq!(
        verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
            alternate_coordinate,
            &commitment_bytes,
            &opening_bytes,
        )
        .unwrap_err(),
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch
    );

    let changed_commitment = mutate_tuple_item(
        &commitment_bytes,
        8,
        CanonicalItem::hash512([101_u8; Hash512::BYTE_LENGTH]),
    );
    assert_eq!(
        verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
            coordinate,
            &changed_commitment,
            &opening_bytes,
        )
        .unwrap_err(),
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentMismatch
    );

    for (item_position, changed_item) in [
        (
            8,
            CanonicalItem::fixed_bytes(
                [103_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
            )
            .unwrap(),
        ),
        (
            9,
            CanonicalItem::fixed_bytes(
                [107_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
            )
            .unwrap(),
        ),
    ] {
        let changed_opening = mutate_tuple_item(&opening_bytes, item_position, changed_item);
        assert_eq!(
            verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
                coordinate,
                &commitment_bytes,
                &changed_opening,
            )
            .unwrap_err(),
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedCommitmentMismatch
        );
    }

    let changed_opening_coordinate =
        mutate_tuple_item(&opening_bytes, 7, CanonicalItem::unsigned16(1));
    assert_eq!(
        verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
            coordinate,
            &commitment_bytes,
            &changed_opening_coordinate,
        )
        .unwrap_err(),
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch
    );
}

#[test]
fn decoders_refuse_wrong_headers_types_lengths_counts_and_trailing_bytes() {
    let context = completion_context(109);
    let subset = completion_subset(&[1, 5, 8]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([113_u8; 64]),
        context,
        Hash512::from_bytes([127_u8; 64]),
        subset,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 0).unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        [131_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [137_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let commitment_bytes = commitment.canonical_bytes().unwrap();
    let opening_bytes = opening.canonical_bytes().unwrap();

    let mut wrong_schema = decode_tuple(&commitment_bytes);
    wrong_schema.schema_identifier = CANONICAL_TUPLE_SCHEMA_IDENTIFIER + 1;
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(
            &wrong_schema.encode().unwrap(),
        ),
        "schema identifier",
    );
    let mut wrong_version = decode_tuple(&commitment_bytes);
    wrong_version.schema_version = CANONICAL_TUPLE_VERSION + 1;
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(
            &wrong_version.encode().unwrap(),
        ),
        "schema version",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &commitment_bytes,
            0,
            CanonicalItem::nonempty_ascii(
                PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_DOMAIN,
            )
            .unwrap(),
        )),
        "object domain",
    );
    let mut missing_item = decode_tuple(&commitment_bytes);
    missing_item.items.pop();
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(
            &missing_item.encode().unwrap(),
        ),
        "item count",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &commitment_bytes,
            7,
            CanonicalItem::unsigned32(0),
        )),
        "contributor position",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(&mutate_tuple_item(
            &commitment_bytes,
            8,
            CanonicalItem::fixed_bytes([0_u8; Hash512::BYTE_LENGTH]).unwrap(),
        )),
        "commitment digest",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(&mutate_tuple_item(
            &opening_bytes,
            8,
            CanonicalItem::fixed_bytes(
                [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH - 1],
            )
            .unwrap(),
        )),
        "commitment salt",
    );
    assert_object_mismatch(
        PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(&mutate_tuple_item(
            &opening_bytes,
            9,
            CanonicalItem::fixed_bytes(
                [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH - 1],
            )
            .unwrap(),
        )),
        "seed contribution",
    );

    let mut trailing_commitment = commitment_bytes.clone();
    trailing_commitment.push(0);
    assert!(matches!(
        PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(&trailing_commitment),
        Err(TallyPreparationError::FoundationCanonicalEncoding(_))
    ));
    let mut oversized_opening = opening_bytes.to_vec();
    oversized_opening.resize(1_025, 0);
    assert!(matches!(
        PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(&oversized_opening),
        Err(TallyPreparationError::FoundationCanonicalEncoding(_))
    ));
}

#[test]
fn every_truncated_commitment_and_opening_prefix_is_refused() {
    let context = completion_context(139);
    let subset = completion_subset(&[2, 4, 7]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([149_u8; 64]),
        context,
        Hash512::from_bytes([151_u8; 64]),
        subset,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 0).unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        [157_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [163_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let commitment_bytes = commitment.canonical_bytes().unwrap();
    let opening_bytes = opening.canonical_bytes().unwrap();

    for prefix_length in 0..commitment_bytes.len() {
        assert!(
            PseudorandomZeroSharingSubsetSeedCommitment320::from_canonical_bytes(
                &commitment_bytes[..prefix_length]
            )
            .is_err()
        );
    }
    for prefix_length in 0..opening_bytes.len() {
        assert!(
            PseudorandomZeroSharingSubsetSeedOpening320::from_canonical_bytes(
                &opening_bytes[..prefix_length]
            )
            .is_err()
        );
    }
}

#[test]
fn scope_and_coordinate_construction_refuse_wrong_rosters_and_nonmembers() {
    let context = completion_context(167);
    let different_roster_subset =
        ReplicatedRandomSharingSubset::from_excluded_positions(7, &[1, 5]).unwrap();
    assert_eq!(
        PseudorandomZeroSharingSubsetSeedScope320::new(
            Hash512::from_bytes([173_u8; 64]),
            context,
            Hash512::from_bytes([179_u8; 64]),
            different_roster_subset,
        ),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedSubsetParticipantCountMismatch {
                subset_participant_count: 7,
                context_participant_count: FOUNDATION_PROFILE.participant_count,
            }
        )
    );

    let subset = completion_subset(&[0, 3, 9]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([181_u8; 64]),
        context,
        Hash512::from_bytes([191_u8; 64]),
        subset,
    )
    .unwrap();
    for invalid_contributor_position in [0, 3, 9, FOUNDATION_PROFILE.participant_count] {
        assert_eq!(
            PseudorandomZeroSharingSubsetSeedCoordinate320::new(
                scope,
                invalid_contributor_position,
            ),
            Err(
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorNotMember {
                    contributor_position: invalid_contributor_position,
                }
            )
        );
    }
}

#[test]
fn combination_refuses_missing_duplicate_and_wrong_scope_contributions() {
    let context = completion_context(193);
    let subset = completion_subset(&[1, 4, 8]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([197_u8; 64]),
        context,
        Hash512::from_bytes([199_u8; 64]),
        subset,
    )
    .unwrap();

    let mut missing = matched_contributions(scope);
    missing.pop();
    assert!(matches!(
        combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(scope, missing),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedInventoryCountMismatch {
                expected: 7,
                actual: 6,
            }
        )
    ));

    let member_positions = subset.member_positions();
    let repeated_position = member_positions[0];
    let mut duplicate = matched_contributions(scope);
    duplicate.pop();
    duplicate.push(matched_contribution(scope, repeated_position));
    assert!(matches!(
        combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(scope, duplicate),
        Err(
            TallyPreparationError::PseudorandomZeroSharingSubsetSeedDuplicateContributor {
                contributor_position,
            }
        ) if contributor_position == repeated_position
    ));

    let alternate_scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        scope.parameter_identity(),
        context,
        Hash512::from_bytes([211_u8; 64]),
        subset,
    )
    .unwrap();
    let mut wrong_scope = matched_contributions(scope);
    wrong_scope.pop();
    wrong_scope.push(matched_contribution(
        alternate_scope,
        *member_positions.last().unwrap(),
    ));
    assert_eq!(
        combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(scope, wrong_scope,)
            .unwrap_err(),
        TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch
    );
}

#[test]
fn zero_secret_values_are_valid_encodings_and_debug_output_redacts_them() {
    let context = completion_context(223);
    let subset = completion_subset(&[2, 6, 9]);
    let scope = PseudorandomZeroSharingSubsetSeedScope320::new(
        Hash512::from_bytes([227_u8; 64]),
        context,
        Hash512::from_bytes([229_u8; 64]),
        subset,
    )
    .unwrap();
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, 0).unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    let matched = verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        &commitment.canonical_bytes().unwrap(),
        &opening.canonical_bytes().unwrap(),
    )
    .unwrap();

    assert!(format!("{opening:?}").contains("[redacted]"));
    assert!(format!("{matched:?}").contains("[redacted]"));
    let master = combine_commitment_matched_pseudorandom_zero_sharing_subset_master_320(
        scope,
        subset
            .member_positions()
            .into_iter()
            .map(|contributor_position| {
                let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(
                    scope,
                    contributor_position,
                )
                .unwrap();
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_subset_seed_contribution_320(
                        coordinate,
                        [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
                        [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
                    )
                    .unwrap();
                verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
                    coordinate,
                    &commitment.canonical_bytes().unwrap(),
                    &opening.canonical_bytes().unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    assert_eq!(master.as_bytes(), &[0_u8; 40]);
    assert!(format!("{master:?}").contains("[redacted]"));
}

fn completion_subset(excluded_positions: &[u16]) -> ReplicatedRandomSharingSubset {
    ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        excluded_positions,
    )
    .unwrap()
}

fn deterministic_contribution(
    subset: ReplicatedRandomSharingSubset,
    contributor_position: u16,
) -> [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH] {
    core::array::from_fn(|byte_position| {
        (subset.excluded_position_mask() as u8)
            .wrapping_mul(17)
            .wrapping_add((contributor_position as u8).wrapping_mul(29))
            .wrapping_add((byte_position as u8).wrapping_mul(31))
    })
}

fn deterministic_salt(
    subset: ReplicatedRandomSharingSubset,
    contributor_position: u16,
) -> [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH] {
    core::array::from_fn(|byte_position| {
        (subset.excluded_position_mask() as u8)
            .wrapping_mul(37)
            .wrapping_add((contributor_position as u8).wrapping_mul(41))
            .wrapping_add((byte_position as u8).wrapping_mul(43))
    })
}

fn commitment_digest(
    scope: PseudorandomZeroSharingSubsetSeedScope320,
    contributor_position: u16,
    contribution: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
    commitment_salt: [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
) -> Hash512 {
    let coordinate =
        PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, contributor_position).unwrap();
    create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        contribution,
        commitment_salt,
    )
    .unwrap()
    .0
    .digest()
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
    result: Result<T, TallyPreparationError>,
    expected_field: &'static str,
) {
    assert!(matches!(
        result,
        Err(TallyPreparationError::PseudorandomZeroSharingSubsetSeedObjectMismatch {
            field,
        }) if field == expected_field
    ));
}

fn matched_contributions(
    scope: PseudorandomZeroSharingSubsetSeedScope320,
) -> Vec<
    super::pseudorandom_zero_sharing_subset_seed_320::CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
>{
    scope
        .subset()
        .member_positions()
        .into_iter()
        .map(|contributor_position| matched_contribution(scope, contributor_position))
        .collect()
}

fn matched_contribution(
    scope: PseudorandomZeroSharingSubsetSeedScope320,
    contributor_position: u16,
) -> super::pseudorandom_zero_sharing_subset_seed_320::CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320
{
    let coordinate =
        PseudorandomZeroSharingSubsetSeedCoordinate320::new(scope, contributor_position).unwrap();
    let contribution = deterministic_contribution(scope.subset(), contributor_position);
    let commitment_salt = deterministic_salt(scope.subset(), contributor_position);
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        contribution,
        commitment_salt,
    )
    .unwrap();
    verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        &commitment.canonical_bytes().unwrap(),
        &opening.canonical_bytes().unwrap(),
    )
    .unwrap()
}

fn completion_context(attempt_byte: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        Hash512::from_bytes([233_u8; 64]),
        Hash512::from_bytes([239_u8; 64]),
        [attempt_byte; 32],
        &circuit,
    )
    .unwrap()
}
