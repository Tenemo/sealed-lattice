use zeroize::Zeroizing;

use crate::{
    foundation::{
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalDecodeLimits,
        CanonicalItemType, CanonicalTuple, FOUNDATION_PROFILE, Hash512,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH,
        CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingPairSeedContributionCoordinate320,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH, SeedCatalogSecretLeafError320,
        create_pseudorandom_zero_sharing_pair_seed_contribution_320,
        pair_seed_coordinate_with_catalog_identity_for_test,
        verify_pseudorandom_zero_sharing_pair_seed_contribution_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        SeedCatalogFixture320, SeedMailboxTestFixture320, seed_catalog_fixture,
        seed_mailbox_test_fixture_320, seed_mailbox_test_fixture_with_parameter_identity_320,
        seed_mailbox_test_fixture_with_parameter_marker_320,
    },
    pseudorandom_zero_sharing_seed_master_join_320::{
        PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN,
        PseudorandomZeroSharingLocalSeedCatalogEntryBytes320,
        PseudorandomZeroSharingSeedMasterJoinError320, combine_pair_master_for_test,
        combine_subset_master_for_test, join_pseudorandom_zero_sharing_seed_masters_320,
        verify_pseudorandom_zero_sharing_local_seed_catalog_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320::{
        RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320_tests::authenticated_delivery_set_with_parameter_identity,
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320_tests::{
        signed_receipt_envelopes_from_authenticated_deliveries,
        signed_receipt_envelopes_from_authenticated_deliveries_with_parameter_identity,
        signed_receipt_envelopes_with_inventory_marker_for_test, signed_terminal_certificate,
        verified_receipt_inventory,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingSubsetMasterScope320,
        PseudorandomZeroSharingSubsetSeedCoordinate320,
        create_pseudorandom_zero_sharing_subset_seed_contribution_320,
        verify_pseudorandom_zero_sharing_subset_seed_contribution_320,
    },
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

struct OwnedLocalSeedCatalogEntry320 {
    opening_bytes: Zeroizing<Vec<u8>>,
    inclusion_proof_bytes: Vec<u8>,
}

impl OwnedLocalSeedCatalogEntry320 {
    fn borrowed(&self) -> PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'_> {
        PseudorandomZeroSharingLocalSeedCatalogEntryBytes320::new(
            &self.opening_bytes,
            &self.inclusion_proof_bytes,
        )
    }
}

#[test]
fn actual_authenticated_receipts_join_every_completion_master_and_unopened_coin_source_and_salt() {
    let participant_position = 0;
    let (
        fixture,
        retained_local_receipt,
        receipt_terminal,
        _,
        local_catalog_fixture,
        local_entries,
    ) = completion_join_fixture(participant_position);
    let local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &fixture.root_terminal,
        participant_position,
        &borrowed_entries(&local_entries),
    )
    .unwrap();
    let expected_authenticated_inventory_identity = retained_local_receipt
        .receipt_body()
        .authenticated_recipient_inventory_identity();
    let joined = join_pseudorandom_zero_sharing_seed_masters_320(
        local_catalog,
        retained_local_receipt,
        receipt_terminal,
    )
    .unwrap();

    let layout = local_catalog_fixture.tree.root_body().layout();
    let expected_subsets = layout
        .coordinates()
        .unwrap()
        .filter_map(|coordinate| match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => Some(subset),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_subsets.len(), 84);
    assert_eq!(joined.subset_masters().len(), expected_subsets.len());
    for (master, subset) in joined.subset_masters().iter().zip(expected_subsets) {
        assert_eq!(master.scope().subset(), subset);
        assert_eq!(
            master.as_bytes(),
            &independent_subset_master(layout, subset)
        );
    }

    let counterparts = (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != participant_position)
        .collect::<Vec<_>>();
    assert_eq!(joined.pair_masters().len(), counterparts.len());
    for (master, counterpart_position) in joined.pair_masters().iter().zip(counterparts) {
        assert_eq!(
            master.scope().lower_roster_position(),
            participant_position.min(counterpart_position)
        );
        assert_eq!(
            master.scope().upper_roster_position(),
            participant_position.max(counterpart_position)
        );
        assert_eq!(
            master.as_bytes(),
            &independent_pair_master(layout, participant_position, counterpart_position)
        );
    }
    assert_eq!(
        joined.collective_coin_source().source(),
        &independent_coin_source(layout)
    );
    assert_eq!(
        joined.collective_coin_source().commitment_salt(),
        &independent_coin_commitment_salt(layout)
    );
    assert_eq!(joined.retained_secret_byte_length().unwrap(), 3_824);
    assert_eq!(joined.participant_position(), participant_position);
    assert_eq!(joined.parameter_identity(), layout.parameter_identity());
    assert_eq!(joined.preparation_context(), layout.preparation_context());
    assert_eq!(
        joined.root_terminal_identity(),
        fixture.root_terminal.identity().unwrap()
    );
    assert_eq!(
        joined.root_terminal_certificate_identity(),
        fixture.root_terminal.certificate_identity()
    );
    assert_eq!(
        joined.authenticated_recipient_inventory_identity(),
        expected_authenticated_inventory_identity
    );
    assert_ne!(
        joined.receipt_terminal_identity(),
        joined.receipt_terminal_certificate_identity()
    );
    assert_ne!(
        joined.receipt_body_identity(),
        joined.receipt_envelope_identity()
    );
    assert!(format!("{joined:?}").contains("[redacted]"));

    let custody_payload_bytes = joined.custody_payload_bytes().unwrap();
    let custody_tuple =
        CanonicalTuple::decode(&custody_payload_bytes, &CanonicalDecodeLimits::default()).unwrap();
    assert_eq!(
        custody_tuple.schema_identifier,
        CANONICAL_TUPLE_SCHEMA_IDENTIFIER
    );
    assert_eq!(custody_tuple.schema_version, CANONICAL_TUPLE_VERSION);
    assert_eq!(custody_tuple.items.len(), 17);
    assert_eq!(
        custody_tuple.items[0].variable_value_bytes().unwrap(),
        PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN.as_bytes()
    );
    assert_eq!(
        custody_tuple.items[1].canonical_bytes(),
        layout.parameter_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[2].variable_value_bytes().unwrap(),
        layout.preparation_context().canonical_bytes()
    );
    assert_eq!(
        custody_tuple.items[3].canonical_bytes(),
        layout.preparation_context().identity().as_bytes()
    );
    assert_eq!(read_custody_u16(&custody_tuple, 4), 0);
    assert_eq!(
        read_custody_u16(&custody_tuple, 5),
        FOUNDATION_PROFILE.participant_count
    );
    assert_eq!(read_custody_u16(&custody_tuple, 6), participant_position);
    assert_eq!(
        custody_tuple.items[7].canonical_bytes(),
        joined.root_terminal_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[8].canonical_bytes(),
        joined.root_terminal_certificate_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[9].canonical_bytes(),
        joined.receipt_terminal_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[10].canonical_bytes(),
        joined.receipt_terminal_certificate_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[11].canonical_bytes(),
        joined
            .authenticated_recipient_inventory_identity()
            .as_bytes()
    );
    assert_eq!(
        custody_tuple.items[12].canonical_bytes(),
        joined.receipt_body_identity().as_bytes()
    );
    assert_eq!(
        custody_tuple.items[13].canonical_bytes(),
        joined.receipt_envelope_identity().as_bytes()
    );
    assert_eq!(read_custody_u16(&custody_tuple, 14), 84);
    assert_eq!(read_custody_u16(&custody_tuple, 15), 9);

    let mut independently_joined_secret_bytes = Zeroizing::new(Vec::new());
    for subset in layout
        .coordinates()
        .unwrap()
        .filter_map(|coordinate| match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => Some(subset),
            _ => None,
        })
    {
        independently_joined_secret_bytes
            .extend_from_slice(&independent_subset_master(layout, subset));
    }
    for counterpart_position in (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != participant_position)
    {
        independently_joined_secret_bytes.extend_from_slice(&independent_pair_master(
            layout,
            participant_position,
            counterpart_position,
        ));
    }
    independently_joined_secret_bytes.extend_from_slice(&independent_coin_commitment_salt(layout));
    independently_joined_secret_bytes.extend_from_slice(&independent_coin_source(layout));
    assert_eq!(independently_joined_secret_bytes.len(), 3_824);
    assert_eq!(
        custody_tuple.items[16].item_type(),
        CanonicalItemType::RawBytes
    );
    assert_eq!(
        custody_tuple.items[16].variable_value_bytes().unwrap(),
        &*independently_joined_secret_bytes
    );

    let independently_derived_payload_byte_length = 8
        + 17 * 6
        + 4
        + PSEUDORANDOM_ZERO_SHARING_JOINED_SEED_MASTER_CUSTODY_DOMAIN.len()
        + 9 * 64
        + 4
        + layout.preparation_context().canonical_bytes().len()
        + 5 * 2
        + 4
        + independently_joined_secret_bytes.len();
    assert_eq!(
        custody_payload_bytes.len(),
        independently_derived_payload_byte_length
    );

    for truncated_byte_length in [0, 1, custody_payload_bytes.len() - 1] {
        assert!(
            CanonicalTuple::decode(
                &custody_payload_bytes[..truncated_byte_length],
                &CanonicalDecodeLimits::default(),
            )
            .is_err()
        );
    }
    let mut payload_with_trailing_byte = custody_payload_bytes.to_vec();
    payload_with_trailing_byte.push(0);
    assert!(
        CanonicalTuple::decode(
            &payload_with_trailing_byte,
            &CanonicalDecodeLimits::default(),
        )
        .is_err()
    );
}

fn read_custody_u16(tuple: &CanonicalTuple, item_index: usize) -> u16 {
    assert_eq!(
        tuple.items[item_index].item_type(),
        CanonicalItemType::Unsigned16
    );
    u16::from_le_bytes(
        tuple.items[item_index]
            .canonical_bytes()
            .try_into()
            .unwrap(),
    )
}

#[test]
fn local_catalog_verifier_requires_every_entry_in_exact_canonical_order() {
    let participant_position = 0;
    let fixture = seed_mailbox_test_fixture_320(1, participant_position);
    let local_catalog_fixture = matching_local_catalog_fixture(&fixture, participant_position);
    let entries = owned_local_entries(&local_catalog_fixture);

    let mut missing = borrowed_entries(&entries);
    missing.pop();
    assert_eq!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &missing,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::LocalCatalogEntryCount {
            expected: 94,
            actual: 93,
        }
    );

    let mut extra = borrowed_entries(&entries);
    extra.push(entries[0].borrowed());
    assert_eq!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &extra,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::LocalCatalogEntryCount {
            expected: 94,
            actual: 95,
        }
    );

    let mut reordered = borrowed_entries(&entries);
    reordered.swap(0, 1);
    assert!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &reordered,
        )
        .is_err()
    );

    let mut malformed_entries = owned_local_entries(&local_catalog_fixture);
    malformed_entries[0].opening_bytes.pop();
    assert!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &borrowed_entries(&malformed_entries),
        )
        .is_err()
    );

    let mut wrong_path_entries = owned_local_entries(&local_catalog_fixture);
    *wrong_path_entries[37]
        .inclusion_proof_bytes
        .last_mut()
        .unwrap() ^= 1;
    assert!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &borrowed_entries(&wrong_path_entries),
        )
        .is_err()
    );

    let unselected_catalog_fixture =
        seed_catalog_fixture(local_catalog_fixture.tree.root_body().layout(), 0xd7);
    let unselected_entries = owned_local_entries(&unselected_catalog_fixture);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_local_seed_catalog_320(
            &fixture.root_terminal,
            participant_position,
            &borrowed_entries(&unselected_entries),
        ),
        Err(PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "local subset contribution verification",
            error: TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch,
        })
    ));
}

#[test]
fn subset_master_combination_refuses_every_noncanonical_contribution_inventory() {
    let parameter_identity = Hash512::from_bytes([0x81; Hash512::BYTE_LENGTH]);
    let preparation_context = completion_context(0x83);
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[7, 8, 9],
    )
    .unwrap();
    let expected_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
        parameter_identity,
        preparation_context,
        subset,
    )
    .unwrap();
    let expected_catalog_identities = catalog_identities(parameter_identity, preparation_context);

    let mut missing = matched_subset_contributions(expected_scope, &expected_catalog_identities);
    missing.pop();
    assert_eq!(
        combine_subset_master_for_test(expected_scope, &expected_catalog_identities, missing,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::InventoryCount {
            inventory: "one subset contribution inventory",
            expected: 7,
            actual: 6,
        }
    );

    let mut extra = matched_subset_contributions(expected_scope, &expected_catalog_identities);
    extra.push(matched_subset_contribution(
        expected_scope,
        expected_catalog_identities[0],
        0,
        0xa1,
    ));
    assert_eq!(
        combine_subset_master_for_test(expected_scope, &expected_catalog_identities, extra,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::InventoryCount {
            inventory: "one subset contribution inventory",
            expected: 7,
            actual: 8,
        }
    );

    let mut reordered = matched_subset_contributions(expected_scope, &expected_catalog_identities);
    reordered.swap(0, 1);
    assert!(matches!(
        combine_subset_master_for_test(expected_scope, &expected_catalog_identities, reordered,),
        Err(PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "subset contribution order",
            error:
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorOrderMismatch {
                    contribution_index: 0,
                    expected_contributor_position: 0,
                    actual_contributor_position: 1,
                },
        })
    ));

    let mut duplicate = matched_subset_contributions(expected_scope, &expected_catalog_identities);
    duplicate[1] =
        matched_subset_contribution(expected_scope, expected_catalog_identities[0], 0, 0xa3);
    assert!(matches!(
        combine_subset_master_for_test(expected_scope, &expected_catalog_identities, duplicate,),
        Err(PseudorandomZeroSharingSeedMasterJoinError320::Preparation {
            phase: "subset contribution order",
            error:
                TallyPreparationError::PseudorandomZeroSharingSubsetSeedContributorOrderMismatch {
                    contribution_index: 1,
                    expected_contributor_position: 1,
                    actual_contributor_position: 0,
                },
        })
    ));

    let mut wrong_parameter =
        matched_subset_contributions(expected_scope, &expected_catalog_identities);
    let alternate_parameter_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
        Hash512::from_bytes([0xa5; Hash512::BYTE_LENGTH]),
        preparation_context,
        subset,
    )
    .unwrap();
    wrong_parameter[6] = matched_subset_contribution(
        alternate_parameter_scope,
        expected_catalog_identities[6],
        6,
        0xa7,
    );
    assert_eq!(
        combine_subset_master_for_test(
            expected_scope,
            &expected_catalog_identities,
            wrong_parameter,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "subset contribution master scope",
        }
    );

    let mut wrong_context =
        matched_subset_contributions(expected_scope, &expected_catalog_identities);
    let alternate_context_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
        parameter_identity,
        completion_context(0xa9),
        subset,
    )
    .unwrap();
    wrong_context[6] = matched_subset_contribution(
        alternate_context_scope,
        expected_catalog_identities[6],
        6,
        0xab,
    );
    assert_eq!(
        combine_subset_master_for_test(
            expected_scope,
            &expected_catalog_identities,
            wrong_context,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "subset contribution master scope",
        }
    );

    let alternate_subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[0, 8, 9],
    )
    .unwrap();
    let alternate_subset_scope = PseudorandomZeroSharingSubsetMasterScope320::new(
        parameter_identity,
        preparation_context,
        alternate_subset,
    )
    .unwrap();
    let mut wrong_subset =
        matched_subset_contributions(expected_scope, &expected_catalog_identities);
    wrong_subset[6] = matched_subset_contribution(
        alternate_subset_scope,
        expected_catalog_identities[6],
        6,
        0xad,
    );
    assert_eq!(
        combine_subset_master_for_test(expected_scope, &expected_catalog_identities, wrong_subset,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "subset contribution master scope",
        }
    );

    let mut wrong_catalog =
        matched_subset_contributions(expected_scope, &expected_catalog_identities);
    wrong_catalog[6] = matched_subset_contribution(
        expected_scope,
        Hash512::from_bytes([0xaf; Hash512::BYTE_LENGTH]),
        6,
        0xb1,
    );
    assert_eq!(
        combine_subset_master_for_test(
            expected_scope,
            &expected_catalog_identities,
            wrong_catalog,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "subset contribution catalog identity",
        }
    );
}

#[test]
fn pair_master_combination_refuses_every_noncanonical_contribution_inventory() {
    let parameter_identity = Hash512::from_bytes([0xb3; Hash512::BYTE_LENGTH]);
    let preparation_context = completion_context(0xb5);
    let lower_position = 2;
    let upper_position = 7;
    let lower_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        preparation_context,
        lower_position,
    )
    .unwrap();
    let expected_scope =
        PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
            lower_layout,
            upper_position,
        )
        .unwrap()
        .scope();
    let expected_catalog_identities = catalog_identities(parameter_identity, preparation_context);

    let mut missing = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    missing.pop();
    assert_eq!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, missing)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::InventoryCount {
            inventory: "one pair contribution inventory",
            expected: 2,
            actual: 1,
        }
    );

    let mut extra = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    extra.push(matched_pair_contribution(
        lower_layout,
        upper_position,
        None,
        0xb7,
    ));
    assert_eq!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, extra)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::InventoryCount {
            inventory: "one pair contribution inventory",
            expected: 2,
            actual: 3,
        }
    );

    let mut reordered = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    reordered.swap(0, 1);
    assert!(matches!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, reordered,),
        Err(PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
            phase: "pair contribution order",
            error: SeedCatalogSecretLeafError320::PairContributorOrderMismatch {
                contribution_index: 0,
                expected_contributor_position: 2,
                actual_contributor_position: 7,
            },
        })
    ));

    let mut duplicate = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    duplicate[1] = matched_pair_contribution(lower_layout, upper_position, None, 0xb9);
    assert!(matches!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, duplicate,),
        Err(PseudorandomZeroSharingSeedMasterJoinError320::SecretLeaf {
            phase: "pair contribution order",
            error: SeedCatalogSecretLeafError320::PairContributorOrderMismatch {
                contribution_index: 1,
                expected_contributor_position: 7,
                actual_contributor_position: 2,
            },
        })
    ));

    let mut wrong_pair = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    wrong_pair[0] = matched_pair_contribution(lower_layout, 8, None, 0xbb);
    assert_eq!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, wrong_pair,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "pair contribution master scope",
        }
    );

    let alternate_parameter = Hash512::from_bytes([0xbd; Hash512::BYTE_LENGTH]);
    let alternate_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        alternate_parameter,
        preparation_context,
        upper_position,
    )
    .unwrap();
    let mut wrong_parameter = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    wrong_parameter[1] = matched_pair_contribution(alternate_layout, lower_position, None, 0xbf);
    assert_eq!(
        combine_pair_master_for_test(
            expected_scope,
            &expected_catalog_identities,
            wrong_parameter,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "pair contribution master scope",
        }
    );

    let alternate_context_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        completion_context(0xc1),
        upper_position,
    )
    .unwrap();
    let mut wrong_context = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    wrong_context[1] =
        matched_pair_contribution(alternate_context_layout, lower_position, None, 0xc3);
    assert_eq!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, wrong_context,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "pair contribution master scope",
        }
    );

    let mut wrong_catalog = matched_pair_contributions(
        parameter_identity,
        preparation_context,
        lower_position,
        upper_position,
    );
    let upper_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        preparation_context,
        upper_position,
    )
    .unwrap();
    wrong_catalog[1] = matched_pair_contribution(
        upper_layout,
        lower_position,
        Some(Hash512::from_bytes([0xc5; Hash512::BYTE_LENGTH])),
        0xc7,
    );
    assert_eq!(
        combine_pair_master_for_test(expected_scope, &expected_catalog_identities, wrong_catalog,)
            .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "pair contribution catalog identity",
        }
    );
}

#[test]
fn join_refuses_an_alternate_public_receipt_carrier_for_the_same_semantic_inventory() {
    let participant_position = 0;
    let (fixture, retained_local_receipt, _, alternate_receipt_terminal, _, local_entries) =
        completion_join_fixture(participant_position);
    let local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &fixture.root_terminal,
        participant_position,
        &borrowed_entries(&local_entries),
    )
    .unwrap();

    assert!(matches!(
        join_pseudorandom_zero_sharing_seed_masters_320(
            local_catalog,
            retained_local_receipt,
            alternate_receipt_terminal,
        ),
        Err(
            PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                field: "retained receipt envelope identity",
            }
        )
    ));
}

#[test]
fn join_refuses_a_local_catalog_verified_under_another_root_terminal() {
    let participant_position = 0;
    let (_, retained_local_receipt, receipt_terminal, _, _, _) =
        completion_join_fixture(participant_position);
    let alternate_fixture =
        seed_mailbox_test_fixture_with_parameter_marker_320(1, participant_position, 0xd9);
    let alternate_catalog_fixture =
        matching_local_catalog_fixture(&alternate_fixture, participant_position);
    let alternate_entries = owned_local_entries(&alternate_catalog_fixture);
    let alternate_local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &alternate_fixture.root_terminal,
        participant_position,
        &borrowed_entries(&alternate_entries),
    )
    .unwrap();

    assert_eq!(
        join_pseudorandom_zero_sharing_seed_masters_320(
            alternate_local_catalog,
            retained_local_receipt,
            receipt_terminal,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "local catalog root-terminal identity",
        }
    );
}

#[test]
fn join_refuses_a_public_receipt_body_that_does_not_match_retained_local_custody() {
    let participant_position = 0;
    let (fixture, retained_local_receipt, _, _, _, local_entries) =
        completion_join_fixture(participant_position);
    let local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &fixture.root_terminal,
        participant_position,
        &borrowed_entries(&local_entries),
    )
    .unwrap();
    let mismatched_receipt_envelopes =
        signed_receipt_envelopes_with_inventory_marker_for_test(&fixture, 0xdb, 0xdd);
    let mismatched_receipt_terminal =
        verified_terminal(&fixture, &mismatched_receipt_envelopes, 0xdf);

    assert_eq!(
        join_pseudorandom_zero_sharing_seed_masters_320(
            local_catalog,
            retained_local_receipt,
            mismatched_receipt_terminal,
        )
        .unwrap_err(),
        PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
            field: "retained receipt body",
        }
    );
}

#[test]
fn join_refuses_local_catalog_custody_for_another_participant() {
    let participant_position = 0;
    let (fixture, retained_local_receipt, receipt_terminal, _, _, _) =
        completion_join_fixture(participant_position);
    let other_participant_position = 1;
    let other_catalog_fixture =
        matching_local_catalog_fixture(&fixture, other_participant_position);
    let other_entries = owned_local_entries(&other_catalog_fixture);
    let other_local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &fixture.root_terminal,
        other_participant_position,
        &borrowed_entries(&other_entries),
    )
    .unwrap();

    assert!(matches!(
        join_pseudorandom_zero_sharing_seed_masters_320(
            other_local_catalog,
            retained_local_receipt,
            receipt_terminal,
        ),
        Err(
            PseudorandomZeroSharingSeedMasterJoinError320::ObjectMismatch {
                field: "local catalog participant position",
            }
        )
    ));
}

fn completion_join_fixture(
    participant_position: u16,
) -> (
    SeedMailboxTestFixture320,
    RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    SeedCatalogFixture320,
    Vec<OwnedLocalSeedCatalogEntry320>,
) {
    assert_eq!(participant_position, 0);
    let fixture = seed_mailbox_test_fixture_320(1, participant_position);
    let (receipt_envelopes, alternate_receipt_envelopes, retained_local_receipt) =
        signed_receipt_envelopes_from_authenticated_deliveries(0x31, 0x41, 0x51);
    let receipt_terminal = verified_terminal(&fixture, &receipt_envelopes, 0x61);
    let alternate_receipt_terminal =
        verified_terminal(&fixture, &alternate_receipt_envelopes, 0x71);
    let local_catalog_fixture = matching_local_catalog_fixture(&fixture, participant_position);
    let local_entries = owned_local_entries(&local_catalog_fixture);
    (
        fixture,
        retained_local_receipt,
        receipt_terminal,
        alternate_receipt_terminal,
        local_catalog_fixture,
        local_entries,
    )
}

pub(super) fn verified_one_and_source_and_joined_custody(
    parameter_identity: Hash512,
) -> (
    SeedMailboxTestFixture320,
    RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320,
    super::pseudorandom_zero_sharing_seed_master_join_320::LocallyJoinedPseudorandomZeroSharingSeedMasters320,
){
    let participant_position = 0;
    let fixture = seed_mailbox_test_fixture_with_parameter_identity_320(
        1,
        participant_position,
        parameter_identity,
    );
    let receipt_envelopes =
        signed_receipt_envelopes_from_authenticated_deliveries_with_parameter_identity(
            parameter_identity,
            0x31,
            0x41,
        );
    let receipt_terminal = verified_terminal(&fixture, &receipt_envelopes, 0x61);
    let (local_delivery_fixture, authenticated_deliveries) =
        authenticated_delivery_set_with_parameter_identity(
            parameter_identity,
            participant_position,
            0x31,
        );
    assert_eq!(
        local_delivery_fixture.root_terminal.identity().unwrap(),
        fixture.root_terminal.identity().unwrap()
    );
    let authenticated_inventory =
        verify_pseudorandom_zero_sharing_authenticated_seed_recipient_inventory_320(
            &local_delivery_fixture.root_terminal,
            participant_position,
            authenticated_deliveries,
        )
        .unwrap();
    let retained_local_receipt = verify_pseudorandom_zero_sharing_seed_recipient_receipt_320(
        &local_delivery_fixture.root_terminal,
        &local_delivery_fixture.roster,
        authenticated_inventory,
        &receipt_envelopes[usize::from(participant_position)],
    )
    .unwrap();
    let local_catalog_fixture = matching_local_catalog_fixture(&fixture, participant_position);
    let local_entries = owned_local_entries(&local_catalog_fixture);
    let local_catalog = verify_pseudorandom_zero_sharing_local_seed_catalog_320(
        &fixture.root_terminal,
        participant_position,
        &borrowed_entries(&local_entries),
    )
    .unwrap();
    let joined_seed_masters = join_pseudorandom_zero_sharing_seed_masters_320(
        local_catalog,
        retained_local_receipt,
        receipt_terminal.clone(),
    )
    .unwrap();
    (fixture, receipt_terminal, joined_seed_masters)
}

fn verified_terminal(
    fixture: &SeedMailboxTestFixture320,
    receipt_envelopes: &[Vec<u8>],
    signature_seed_marker: u8,
) -> RosterEndorsedPseudorandomZeroSharingSeedRecipientReceiptTerminal320 {
    let receipt_inventory = verified_receipt_inventory(fixture, receipt_envelopes);
    let certificate = signed_terminal_certificate(
        &receipt_inventory,
        &fixture.signing_keys,
        signature_seed_marker,
        super::pseudorandom_zero_sharing_seed_receipt_terminal_320::PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );
    verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        fixture.root_terminal.clone(),
        receipt_inventory,
        &fixture.roster,
        &certificate.canonical_bytes().unwrap(),
    )
    .unwrap()
}

fn matching_local_catalog_fixture(
    fixture: &SeedMailboxTestFixture320,
    participant_position: u16,
) -> SeedCatalogFixture320 {
    let layout = fixture
        .root_terminal
        .root_inventory()
        .root_body(participant_position)
        .unwrap()
        .layout();
    let catalog_fixture =
        seed_catalog_fixture(layout, 0x21_u8.wrapping_add(participant_position as u8));
    assert_eq!(
        catalog_fixture.tree.root_body(),
        fixture
            .root_terminal
            .root_inventory()
            .root_body(participant_position)
            .unwrap()
    );
    catalog_fixture
}

fn owned_local_entries(fixture: &SeedCatalogFixture320) -> Vec<OwnedLocalSeedCatalogEntry320> {
    fixture
        .opening_bytes
        .iter()
        .enumerate()
        .map(
            |(leaf_index, opening_bytes)| OwnedLocalSeedCatalogEntry320 {
                opening_bytes: Zeroizing::new(opening_bytes.to_vec()),
                inclusion_proof_bytes: fixture
                    .tree
                    .inclusion_proof(leaf_index as u64)
                    .unwrap()
                    .canonical_bytes()
                    .unwrap(),
            },
        )
        .collect()
}

fn borrowed_entries(
    entries: &[OwnedLocalSeedCatalogEntry320],
) -> Vec<PseudorandomZeroSharingLocalSeedCatalogEntryBytes320<'_>> {
    entries
        .iter()
        .map(OwnedLocalSeedCatalogEntry320::borrowed)
        .collect()
}

fn matched_subset_contributions(
    master_scope: PseudorandomZeroSharingSubsetMasterScope320,
    catalog_identities: &[Hash512],
) -> Vec<CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320> {
    master_scope
        .subset()
        .member_positions()
        .into_iter()
        .map(|contributor_position| {
            matched_subset_contribution(
                master_scope,
                catalog_identities[usize::from(contributor_position)],
                contributor_position,
                0xe1_u8.wrapping_add(contributor_position as u8),
            )
        })
        .collect()
}

fn matched_subset_contribution(
    master_scope: PseudorandomZeroSharingSubsetMasterScope320,
    seed_catalog_identity: Hash512,
    contributor_position: u16,
    secret_marker: u8,
) -> CommitmentMatchedPseudorandomZeroSharingSubsetSeedContribution320 {
    let coordinate = PseudorandomZeroSharingSubsetSeedCoordinate320::new(
        master_scope,
        seed_catalog_identity,
        contributor_position,
    )
    .unwrap();
    let (commitment, opening) = create_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        [secret_marker; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH],
        [secret_marker.wrapping_add(1);
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    verify_pseudorandom_zero_sharing_subset_seed_contribution_320(
        coordinate,
        &commitment.canonical_bytes().unwrap(),
        &opening.canonical_bytes().unwrap(),
    )
    .unwrap()
}

fn matched_pair_contributions(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    lower_position: u16,
    upper_position: u16,
) -> Vec<CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320> {
    [lower_position, upper_position]
        .into_iter()
        .map(|contributor_position| {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                preparation_context,
                contributor_position,
            )
            .unwrap();
            let counterpart_position = if contributor_position == lower_position {
                upper_position
            } else {
                lower_position
            };
            matched_pair_contribution(
                layout,
                counterpart_position,
                None,
                0xe9_u8.wrapping_add(contributor_position as u8),
            )
        })
        .collect()
}

fn matched_pair_contribution(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    counterpart_position: u16,
    catalog_identity_override: Option<Hash512>,
    secret_marker: u8,
) -> CommitmentMatchedPseudorandomZeroSharingPairSeedContribution320 {
    let coordinate = PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
        layout,
        counterpart_position,
    )
    .unwrap();
    let coordinate = catalog_identity_override.map_or(coordinate, |catalog_identity| {
        pair_seed_coordinate_with_catalog_identity_for_test(coordinate, catalog_identity)
    });
    let (commitment, opening) = create_pseudorandom_zero_sharing_pair_seed_contribution_320(
        coordinate,
        [secret_marker; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH],
        [secret_marker.wrapping_add(1); SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH],
    )
    .unwrap();
    verify_pseudorandom_zero_sharing_pair_seed_contribution_320(
        coordinate,
        &commitment.canonical_bytes().unwrap(),
        &opening.canonical_bytes().unwrap(),
    )
    .unwrap()
}

fn catalog_identities(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
) -> Vec<Hash512> {
    (0..FOUNDATION_PROFILE.participant_count)
        .map(|contributor_position| {
            PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                preparation_context,
                contributor_position,
            )
            .unwrap()
            .identity()
        })
        .collect()
}

fn completion_context(attempt_marker: u8) -> TallyPreparationContext {
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
        Hash512::from_bytes([0xeb; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0xed; Hash512::BYTE_LENGTH]),
        [attempt_marker; 32],
        &circuit,
    )
    .unwrap()
}

fn independent_subset_master(
    participant_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    subset: ReplicatedRandomSharingSubset,
) -> [u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH] {
    let mut master = [0_u8; PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH];
    for contributor_position in subset.member_positions() {
        let contributor_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
            participant_layout.parameter_identity(),
            participant_layout.preparation_context(),
            contributor_position,
        )
        .unwrap();
        let leaf_ordinal = contributor_layout
            .leaf_ordinal(PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(
                subset,
            ))
            .unwrap();
        let catalog_marker = 0x21_u8.wrapping_add(contributor_position as u8);
        let contribution = marked_bytes::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        >(catalog_marker.wrapping_add(0x21), leaf_ordinal);
        for (master_byte, contribution_byte) in master.iter_mut().zip(contribution) {
            *master_byte ^= contribution_byte;
        }
    }
    master
}

fn independent_pair_master(
    participant_layout: PseudorandomZeroSharingSeedCatalogLayout320,
    participant_position: u16,
    counterpart_position: u16,
) -> [u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH] {
    let pair_coordinate = participant_layout
        .pair_coordinate(counterpart_position)
        .unwrap();
    let PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
        lower_roster_position,
        upper_roster_position,
    } = pair_coordinate
    else {
        unreachable!();
    };
    assert!(
        participant_position == lower_roster_position
            || participant_position == upper_roster_position
    );
    let mut master = [0_u8; PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH];
    for contributor_position in [lower_roster_position, upper_roster_position] {
        let contributor_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
            participant_layout.parameter_identity(),
            participant_layout.preparation_context(),
            contributor_position,
        )
        .unwrap();
        let other_position = if contributor_position == lower_roster_position {
            upper_roster_position
        } else {
            lower_roster_position
        };
        let leaf_ordinal = contributor_layout
            .leaf_ordinal(contributor_layout.pair_coordinate(other_position).unwrap())
            .unwrap();
        let catalog_marker = 0x21_u8.wrapping_add(contributor_position as u8);
        let contribution = marked_bytes::<
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        >(catalog_marker.wrapping_add(0x41), leaf_ordinal);
        for (master_byte, contribution_byte) in master.iter_mut().zip(contribution) {
            *master_byte ^= contribution_byte;
        }
    }
    master
}

fn independent_coin_source(
    participant_layout: PseudorandomZeroSharingSeedCatalogLayout320,
) -> [u8; COLLECTIVE_COIN_SOURCE_BYTE_LENGTH] {
    let leaf_ordinal = participant_layout
        .leaf_ordinal(PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin)
        .unwrap();
    let catalog_marker = 0x21_u8.wrapping_add(participant_layout.contributor_position() as u8);
    marked_bytes::<COLLECTIVE_COIN_SOURCE_BYTE_LENGTH>(
        catalog_marker.wrapping_add(0x51),
        leaf_ordinal,
    )
}

fn independent_coin_commitment_salt(
    participant_layout: PseudorandomZeroSharingSeedCatalogLayout320,
) -> [u8; SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH] {
    let leaf_ordinal = participant_layout
        .leaf_ordinal(PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin)
        .unwrap();
    let catalog_marker = 0x21_u8.wrapping_add(participant_layout.contributor_position() as u8);
    marked_bytes::<SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH>(
        catalog_marker.wrapping_add(0x11),
        leaf_ordinal,
    )
}

fn marked_bytes<const BYTE_LENGTH: usize>(marker: u8, ordinal: u64) -> [u8; BYTE_LENGTH] {
    let mut bytes = [marker; BYTE_LENGTH];
    let ordinal_bytes = ordinal.to_le_bytes();
    let copied_byte_length = BYTE_LENGTH.min(ordinal_bytes.len());
    bytes[..copied_byte_length].copy_from_slice(&ordinal_bytes[..copied_byte_length]);
    bytes
}
