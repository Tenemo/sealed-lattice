use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};
use zeroize::Zeroizing;

use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, Roster, RosterEntry,
        derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, CollectiveCoinSourceCoordinate320,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PseudorandomZeroSharingPairSeedContributionCoordinate320,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH, create_collective_coin_source_320,
        create_pseudorandom_zero_sharing_pair_seed_contribution_320,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
        PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_BODY_DOMAIN,
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320,
        PseudorandomZeroSharingSeedCatalogRootInventoryError,
        VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320,
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320,
        PseudorandomZeroSharingSeedCatalogRootTerminalError320,
        RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320,
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320,
    },
    pseudorandom_zero_sharing_seed_catalog_state_output_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
        PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320,
        PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320,
    },
    pseudorandom_zero_sharing_seed_delivery_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_BODY_BYTE_LENGTH,
        PseudorandomZeroSharingSeedDeliveryEntryBytes320,
        PseudorandomZeroSharingSeedDeliveryError320, PseudorandomZeroSharingSeedDeliveryLayout320,
        RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320,
        derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320,
        verify_pseudorandom_zero_sharing_seed_delivery_320,
        verify_pseudorandom_zero_sharing_seed_recipient_inventory_320,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        create_pseudorandom_zero_sharing_subset_seed_contribution_320,
    },
};

const COMPLETION_ROOT_INVENTORY_BODY_BYTE_LENGTH: usize = 931;

#[derive(Clone)]
struct OwnedRootAuthorizationPackage320 {
    root_body_bytes: Vec<u8>,
    reservation_certificate_bytes: Vec<u8>,
    exact_output_certificate_bytes: Vec<u8>,
    contributor_signature_envelope_bytes: Vec<u8>,
}

impl OwnedRootAuthorizationPackage320 {
    fn borrowed(&self) -> PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'_> {
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320::new(
            &self.root_body_bytes,
            &self.reservation_certificate_bytes,
            &self.exact_output_certificate_bytes,
            &self.contributor_signature_envelope_bytes,
        )
    }
}

struct SeedCatalogFixture320 {
    tree: PseudorandomZeroSharingSeedCatalogTree320,
    opening_bytes: Box<[Zeroizing<Vec<u8>>]>,
}

struct OwnedSeedDeliveryEntry320 {
    opening_bytes: Zeroizing<Vec<u8>>,
    inclusion_proof_bytes: Vec<u8>,
}

pub(super) struct SeedMailboxTestFixture320 {
    pub(super) roster: Roster,
    pub(super) signing_keys: Vec<ml_dsa_65::PrivateKey>,
    pub(super) mailbox_decapsulation_keys: Vec<ml_kem_768::DecapsKey>,
    pub(super) root_terminal: RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    pub(super) sender_position: u16,
    pub(super) recipient_position: u16,
    pub(super) descriptor_bytes: Vec<u8>,
    pub(super) payload_bytes: Zeroizing<Vec<u8>>,
}

pub(super) fn seed_mailbox_test_fixture_320(
    sender_position: u16,
    recipient_position: u16,
) -> SeedMailboxTestFixture320 {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    assert!(sender_position < participant_count);
    assert!(recipient_position < participant_count);
    assert_ne!(sender_position, recipient_position);
    let (roster, signing_keys, mailbox_decapsulation_keys) =
        roster_signing_and_mailbox_keys(participant_count, 0x19);
    let preparation_context = build_preparation_context(&roster, 0x1b);
    let parameter_identity = deterministic_hash(0x1d, 0);
    let catalog_fixtures = (0..participant_count)
        .map(|contributor_position| {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                preparation_context,
                contributor_position,
            )
            .unwrap();
            seed_catalog_fixture(layout, 0x21_u8.wrapping_add(contributor_position as u8))
        })
        .collect::<Vec<_>>();
    let owned_packages = catalog_fixtures
        .iter()
        .enumerate()
        .map(|(contributor_index, fixture)| {
            authorize_root_body(
                fixture.tree.root_body(),
                &roster,
                &signing_keys,
                0x41_u8.wrapping_add(contributor_index as u8),
                false,
            )
        })
        .collect::<Vec<_>>();
    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&owned_packages),
    )
    .unwrap();
    let terminal_certificate =
        signed_root_terminal_certificate(&root_inventory, &signing_keys, 0x61);
    let root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory,
        &roster,
        &terminal_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();
    let descriptor_bytes = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        &root_terminal,
        sender_position,
        recipient_position,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    let entries = seed_delivery_entries(
        &catalog_fixtures[usize::from(sender_position)],
        recipient_position,
    );
    let payload_byte_length = entries
        .iter()
        .map(|entry| entry.opening_bytes.len() + entry.inclusion_proof_bytes.len())
        .sum();
    let mut payload_bytes = Zeroizing::new(Vec::with_capacity(payload_byte_length));
    for entry in entries {
        payload_bytes.extend_from_slice(&entry.opening_bytes);
        payload_bytes.extend_from_slice(&entry.inclusion_proof_bytes);
    }
    SeedMailboxTestFixture320 {
        roster,
        signing_keys,
        mailbox_decapsulation_keys,
        root_terminal,
        sender_position,
        recipient_position,
        descriptor_bytes,
        payload_bytes,
    }
}

impl OwnedSeedDeliveryEntry320 {
    fn borrowed(&self) -> PseudorandomZeroSharingSeedDeliveryEntryBytes320<'_> {
        PseudorandomZeroSharingSeedDeliveryEntryBytes320::new(
            &self.opening_bytes,
            &self.inclusion_proof_bytes,
        )
    }
}

#[test]
fn every_admitted_roster_forms_one_formula_derived_ordered_root_inventory() {
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_BODY_DOMAIN,
        "sealed-lattice/v1/preparation/seed-catalog-root-inventory"
    );
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let marker = 0x21_u8.wrapping_add(participant_count as u8);
        let (roster, signing_keys) = roster_and_signing_keys(participant_count, marker);
        let preparation_context = build_preparation_context(&roster, marker.wrapping_add(0x10));
        let parameter_identity = deterministic_hash(marker.wrapping_add(0x20), 0);
        let owned_packages = root_authorization_packages(
            parameter_identity,
            preparation_context,
            &roster,
            &signing_keys,
            marker.wrapping_add(0x30),
            false,
        );
        let packages = borrowed_packages(&owned_packages);
        let verified_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &packages,
        )
        .unwrap();

        assert_eq!(
            verified_inventory.authorized_roots().len(),
            usize::from(participant_count)
        );
        assert_eq!(
            verified_inventory.body().parameter_identity(),
            parameter_identity
        );
        assert_eq!(
            verified_inventory.body().preparation_context_identity(),
            preparation_context.identity()
        );
        assert_eq!(
            verified_inventory.body().participant_count(),
            participant_count
        );
        for contributor_position in 0..participant_count {
            let root_body = verified_inventory.root_body(contributor_position).unwrap();
            assert_eq!(
                root_body.layout().contributor_position(),
                contributor_position
            );
            assert_eq!(
                verified_inventory.body().root_body_identities()[usize::from(contributor_position)],
                root_body.identity().unwrap()
            );
        }
        assert!(verified_inventory.root_body(participant_count).is_none());

        let expected_body_byte_length = 231 + usize::from(participant_count) * 70;
        assert_eq!(
            verified_inventory.body().canonical_bytes().unwrap().len(),
            expected_body_byte_length
        );
        if participant_count == FOUNDATION_PROFILE.participant_count {
            assert_eq!(
                expected_body_byte_length,
                COMPLETION_ROOT_INVENTORY_BODY_BYTE_LENGTH
            );
        }
    }
}

#[test]
fn inventory_identity_ignores_authorization_carrier_choices_and_binds_every_root() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let (roster, signing_keys) = roster_and_signing_keys(participant_count, 0x71);
    let preparation_context = build_preparation_context(&roster, 0x73);
    let parameter_identity = deterministic_hash(0x75, 0);
    let first_owned_packages = root_authorization_packages(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0x77,
        false,
    );
    let mut alternate_authorization_packages = first_owned_packages.clone();
    alternate_authorization_packages[0] = root_authorization_package(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0,
        0x77,
        true,
    );
    let mut changed_root_packages = first_owned_packages.clone();
    changed_root_packages[0] = root_authorization_package(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0,
        0x79,
        false,
    );

    let first_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&first_owned_packages),
    )
    .unwrap();
    let alternate_authorization_inventory =
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &borrowed_packages(&alternate_authorization_packages),
        )
        .unwrap();
    let changed_root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&changed_root_packages),
    )
    .unwrap();

    assert_eq!(
        first_inventory.body().canonical_bytes().unwrap(),
        alternate_authorization_inventory
            .body()
            .canonical_bytes()
            .unwrap()
    );
    assert_eq!(
        first_inventory.identity().unwrap(),
        alternate_authorization_inventory.identity().unwrap(),
        "different valid witness subsets must not create another semantic root inventory"
    );
    assert_ne!(
        first_inventory.authorized_roots()[0].reservation_certificate_identity(),
        alternate_authorization_inventory.authorized_roots()[0].reservation_certificate_identity()
    );
    assert_ne!(
        first_inventory.authorized_roots()[0].exact_output_certificate_identity(),
        alternate_authorization_inventory.authorized_roots()[0].exact_output_certificate_identity()
    );
    assert_ne!(
        first_inventory.identity().unwrap(),
        changed_root_inventory.identity().unwrap()
    );
    assert_ne!(
        first_inventory.root_body(0).unwrap().identity().unwrap(),
        changed_root_inventory
            .root_body(0)
            .unwrap()
            .identity()
            .unwrap()
    );
    for contributor_position in 1..participant_count {
        assert_eq!(
            first_inventory.root_body(contributor_position),
            changed_root_inventory.root_body(contributor_position)
        );
    }
}

#[test]
fn root_terminal_requires_all_roster_endorsements_and_separates_semantics_from_carriers() {
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_DOMAIN,
        "sealed-lattice/v1/preparation/seed-catalog-root-terminal"
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH,
        144
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_AUTHORIZATION_BODY_BYTE_LENGTH,
        169
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_ENDORSEMENT_ENVELOPE_BYTE_LENGTH,
        3_589
    );

    let participant_count = FOUNDATION_PROFILE.participant_count;
    let (roster, signing_keys) = roster_and_signing_keys(participant_count, 0x81);
    let preparation_context = build_preparation_context(&roster, 0x83);
    let parameter_identity = deterministic_hash(0x85, 0);
    let owned_packages = root_authorization_packages(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0x87,
        false,
    );
    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&owned_packages),
    )
    .unwrap();
    let terminal_body =
        PseudorandomZeroSharingSeedCatalogRootTerminalBody320::new(&root_inventory).unwrap();
    let first_certificate = signed_root_terminal_certificate(&root_inventory, &signing_keys, 0x91);
    let alternate_signature_certificate =
        signed_root_terminal_certificate(&root_inventory, &signing_keys, 0xa1);

    assert_eq!(
        terminal_body.root_inventory_identity(),
        root_inventory.identity().unwrap()
    );
    assert_eq!(terminal_body.participant_count(), participant_count);
    assert_eq!(
        terminal_body.canonical_bytes().unwrap().len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_BODY_BYTE_LENGTH
    );
    let expected_certificate_byte_length =
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::canonical_byte_length_for_participant_count(
            participant_count,
        )
        .unwrap();
    assert_eq!(expected_certificate_byte_length, 36_230);
    assert_eq!(
        first_certificate.canonical_bytes().unwrap().len(),
        expected_certificate_byte_length
    );
    assert_eq!(first_certificate.endorsement_envelopes().len(), 10);
    assert!(format!("{first_certificate:?}").contains("[redacted]"));
    assert!(format!("{:?}", first_certificate.endorsement_envelopes()[0]).contains("[redacted]"));

    let first_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        root_inventory.clone(),
        &roster,
        &first_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();
    let alternate_signature_terminal =
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
            root_inventory,
            &roster,
            &alternate_signature_certificate.canonical_bytes().unwrap(),
        )
        .unwrap();
    assert_eq!(first_terminal.terminal_body(), terminal_body);
    assert_eq!(
        first_terminal.identity().unwrap(),
        terminal_body.identity().unwrap()
    );
    assert_eq!(
        first_terminal.identity().unwrap(),
        alternate_signature_terminal.identity().unwrap(),
        "different valid signature randomness must not fork the semantic terminal"
    );
    assert_ne!(
        first_terminal.certificate_identity(),
        alternate_signature_terminal.certificate_identity(),
        "carrier identities must still bind the exact signatures"
    );
    assert_eq!(
        first_terminal.root_inventory().identity().unwrap(),
        terminal_body.root_inventory_identity()
    );
}

#[test]
fn root_terminal_refuses_incomplete_reordered_forged_and_mismatched_endorsements() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let (roster, signing_keys) = roster_and_signing_keys(participant_count, 0xb1);
    let preparation_context = build_preparation_context(&roster, 0xb3);
    let parameter_identity = deterministic_hash(0xb5, 0);
    let owned_packages = root_authorization_packages(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0xb7,
        false,
    );
    let root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&owned_packages),
    )
    .unwrap();
    let terminal_body =
        PseudorandomZeroSharingSeedCatalogRootTerminalBody320::new(&root_inventory).unwrap();
    let endorsement_envelopes =
        signed_root_terminal_endorsement_envelopes(terminal_body, &signing_keys, 0xc1);

    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::new(
            terminal_body,
            endorsement_envelopes[..endorsement_envelopes.len() - 1].to_vec(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementCount {
                expected: 10,
                actual: 9,
            }
        )
    ));
    let mut extra_endorsements = endorsement_envelopes.clone();
    extra_endorsements.push(endorsement_envelopes[0].clone());
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::new(
            terminal_body,
            extra_endorsements,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementCount {
                expected: 10,
                actual: 11,
            }
        )
    ));
    let mut reordered_endorsements = endorsement_envelopes.clone();
    reordered_endorsements.swap(2, 3);
    assert_eq!(
        PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::new(
            terminal_body,
            reordered_endorsements,
        ),
        Err(PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorsementOrder)
    );
    assert!(matches!(
        PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320::new(
            terminal_body,
            participant_count,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::EndorserPositionOutOfRange {
                endorser_position: 10,
                participant_count: 10,
            }
        )
    ));

    let certificate = PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::new(
        terminal_body,
        endorsement_envelopes,
    )
    .unwrap();
    let certificate_bytes = certificate.canonical_bytes().unwrap();
    let mut forged_certificate_bytes = certificate_bytes.clone();
    *forged_certificate_bytes.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
            root_inventory.clone(),
            &roster,
            &forged_certificate_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::InvalidEndorsementSignature {
                endorser_position: 9,
            }
        )
    ));

    let (wrong_roster, _) = roster_and_signing_keys(participant_count, 0xd1);
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
            root_inventory.clone(),
            &wrong_roster,
            &certificate_bytes,
        ),
        Err(PseudorandomZeroSharingSeedCatalogRootTerminalError320::RosterMismatch)
    );

    let changed_packages = root_authorization_packages(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0xd3,
        false,
    );
    let changed_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&changed_packages),
    )
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
            changed_inventory,
            &roster,
            &certificate_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootTerminalError320::ObjectMismatch {
                field: "root-inventory identity",
            }
        )
    ));

    for truncated_length in [0, 1, 7, 8, 143, 1_024, certificate_bytes.len() - 1] {
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
                root_inventory.clone(),
                &roster,
                &certificate_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    assert!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
            root_inventory,
            &roster,
            &vec![0_u8; 131_073],
        )
        .is_err()
    );
}

#[test]
fn root_inventory_refuses_missing_reordered_mixed_and_wrong_context_packages() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let (roster, signing_keys) = roster_and_signing_keys(participant_count, 0xa1);
    let preparation_context = build_preparation_context(&roster, 0xa3);
    let parameter_identity = deterministic_hash(0xa5, 0);
    let owned_packages = root_authorization_packages(
        parameter_identity,
        preparation_context,
        &roster,
        &signing_keys,
        0xa7,
        false,
    );
    let packages = borrowed_packages(&owned_packages);

    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &packages[..packages.len() - 1],
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::PackageCount {
                expected: usize::from(participant_count),
                actual: usize::from(participant_count) - 1,
            }
        )
    );
    let mut extra_packages = packages.clone();
    extra_packages.push(owned_packages[0].borrowed());
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &extra_packages,
        ),
        Err(PseudorandomZeroSharingSeedCatalogRootInventoryError::PackageCount { .. })
    ));

    let mut reordered_packages = packages.clone();
    reordered_packages.swap(0, 1);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &reordered_packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 0,
                ..
            }
        )
    ));
    let mut duplicate_packages = packages.clone();
    duplicate_packages[1] = duplicate_packages[0];
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &duplicate_packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 1,
                ..
            }
        )
    ));

    let mut mixed_certificate_packages = packages.clone();
    mixed_certificate_packages[3] =
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320::new(
            &owned_packages[3].root_body_bytes,
            &owned_packages[4].reservation_certificate_bytes,
            &owned_packages[3].exact_output_certificate_bytes,
            &owned_packages[3].contributor_signature_envelope_bytes,
        );
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &mixed_certificate_packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 3,
                ..
            }
        )
    ));

    let mut changed_signature_packages = owned_packages.clone();
    *changed_signature_packages[4]
        .contributor_signature_envelope_bytes
        .last_mut()
        .unwrap() ^= 0x80;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &roster,
            &borrowed_packages(&changed_signature_packages),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 4,
                ..
            }
        )
    ));

    let (wrong_roster, _) = roster_and_signing_keys(participant_count, 0xb1);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            preparation_context,
            &wrong_roster,
            &packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 0,
                ..
            }
        )
    ));
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            deterministic_hash(0xb3, 0),
            preparation_context,
            &roster,
            &packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 0,
                ..
            }
        )
    ));
    let wrong_preparation_context = build_preparation_context(&roster, 0xb5);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
            parameter_identity,
            wrong_preparation_context,
            &roster,
            &packages,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogRootInventoryError::RootAuthorization {
                contributor_position: 0,
                ..
            }
        )
    ));

    let package_debug = format!("{:?}", packages[0]);
    assert!(package_debug.contains("[redacted]"));
}

#[test]
fn ordered_seed_deliveries_require_the_roster_root_terminal_before_mailbox_authority() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let (roster, signing_keys) = roster_and_signing_keys(participant_count, 0xc1);
    let preparation_context = build_preparation_context(&roster, 0xc3);
    let parameter_identity = deterministic_hash(0xc5, 0);
    let catalog_fixtures = (0..participant_count)
        .map(|sender_position| {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                preparation_context,
                sender_position,
            )
            .unwrap();
            seed_catalog_fixture(layout, 0xc7_u8.wrapping_add(sender_position as u8))
        })
        .collect::<Vec<_>>();
    let owned_packages = catalog_fixtures
        .iter()
        .enumerate()
        .map(|(sender_index, fixture)| {
            authorize_root_body(
                fixture.tree.root_body(),
                &roster,
                &signing_keys,
                0xd1_u8.wrapping_add(sender_index as u8),
                false,
            )
        })
        .collect::<Vec<_>>();
    let verified_root_inventory = verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320(
        parameter_identity,
        preparation_context,
        &roster,
        &borrowed_packages(&owned_packages),
    )
    .unwrap();
    let root_terminal_certificate =
        signed_root_terminal_certificate(&verified_root_inventory, &signing_keys, 0xe1);
    let verified_root_terminal = verify_pseudorandom_zero_sharing_seed_catalog_root_terminal_320(
        verified_root_inventory,
        &roster,
        &root_terminal_certificate.canonical_bytes().unwrap(),
    )
    .unwrap();

    let sender_position = 2;
    let recipient_position = 7;
    let descriptor = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        &verified_root_terminal,
        sender_position,
        recipient_position,
    )
    .unwrap();
    let descriptor_bytes = descriptor.canonical_bytes().unwrap();
    let owned_entries = seed_delivery_entries(
        &catalog_fixtures[usize::from(sender_position)],
        recipient_position,
    );
    let entries = borrowed_delivery_entries(&owned_entries);
    let expected_layout = PseudorandomZeroSharingSeedDeliveryLayout320::derive(
        catalog_fixtures[usize::from(sender_position)]
            .tree
            .root_body()
            .layout(),
        recipient_position,
    )
    .unwrap();

    assert_eq!(
        descriptor_bytes.len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_DELIVERY_DESCRIPTOR_BODY_BYTE_LENGTH
    );
    assert_eq!(descriptor.parameter_identity(), parameter_identity);
    assert_eq!(
        descriptor.preparation_context_identity(),
        preparation_context.identity()
    );
    assert_eq!(
        descriptor.root_terminal_identity(),
        verified_root_terminal.identity().unwrap()
    );
    assert_eq!(descriptor.participant_count(), participant_count);
    assert_eq!(descriptor.sender_position(), sender_position);
    assert_eq!(descriptor.recipient_position(), recipient_position);
    assert_eq!(descriptor.payload_byte_length(), 62_590);
    assert_eq!(entries.len(), 57);
    assert_eq!(
        owned_entries
            .iter()
            .map(|entry| entry.opening_bytes.len() + entry.inclusion_proof_bytes.len())
            .sum::<usize>(),
        expected_layout.payload_byte_length()
    );

    let verified_delivery = verify_pseudorandom_zero_sharing_seed_delivery_320(
        &verified_root_terminal,
        sender_position,
        recipient_position,
        &descriptor_bytes,
        &entries,
    )
    .unwrap();
    assert_eq!(verified_delivery.descriptor(), descriptor);
    assert_eq!(verified_delivery.layout(), &expected_layout);
    assert_eq!(verified_delivery.subset_entries().len(), 56);
    for (entry, expected_subset) in verified_delivery
        .subset_entries()
        .iter()
        .zip(expected_layout.subsets())
    {
        assert_eq!(entry.subset(), *expected_subset);
        let _ = entry.contribution();
    }
    let pair_scope = verified_delivery.pair_contribution().coordinate().scope();
    assert_eq!(pair_scope.lower_roster_position(), sender_position);
    assert_eq!(pair_scope.upper_roster_position(), recipient_position);
    assert_eq!(
        verified_delivery.identity().unwrap(),
        descriptor.identity().unwrap()
    );
    assert!(format!("{verified_delivery:?}").contains("[redacted]"));
    assert!(format!("{:?}", entries[0]).contains("[redacted]"));

    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &descriptor_bytes,
            &entries[..entries.len() - 1],
        ),
        Err(
            PseudorandomZeroSharingSeedDeliveryError320::DeliveryEntryCount {
                expected: 57,
                actual: 56,
            }
        )
    ));
    let mut reordered_entries = entries.clone();
    reordered_entries.swap(0, 1);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &descriptor_bytes,
            &reordered_entries,
        ),
        Err(PseudorandomZeroSharingSeedDeliveryError320::Preparation(
            super::TallyPreparationError::PseudorandomZeroSharingSubsetSeedCoordinateMismatch
        ))
    ));
    let mut changed_proof_entries = seed_delivery_entries(
        &catalog_fixtures[usize::from(sender_position)],
        recipient_position,
    );
    *changed_proof_entries[0]
        .inclusion_proof_bytes
        .last_mut()
        .unwrap() ^= 0x40;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &descriptor_bytes,
            &borrowed_delivery_entries(&changed_proof_entries),
        ),
        Err(PseudorandomZeroSharingSeedDeliveryError320::Preparation(
            super::TallyPreparationError::PseudorandomZeroSharingSeedCatalogRootMismatch
        ))
    ));
    let other_recipient_descriptor = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
        &verified_root_terminal,
        sender_position,
        recipient_position + 1,
    )
    .unwrap()
    .canonical_bytes()
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &other_recipient_descriptor,
            &entries,
        ),
        Err(
            PseudorandomZeroSharingSeedDeliveryError320::DescriptorMismatch {
                field: "recipient position"
            }
        )
    ));
    let mut changed_descriptor_bytes = descriptor_bytes.clone();
    *changed_descriptor_bytes.last_mut().unwrap() ^= 0x80;
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &changed_descriptor_bytes,
            &entries,
        ),
        Err(
            PseudorandomZeroSharingSeedDeliveryError320::DescriptorMismatch {
                field: "payload byte length"
            }
        )
    ));
    for truncated_length in 0..descriptor_bytes.len() {
        assert!(
            verify_pseudorandom_zero_sharing_seed_delivery_320(
                &verified_root_terminal,
                sender_position,
                recipient_position,
                &descriptor_bytes[..truncated_length],
                &entries,
            )
            .is_err()
        );
    }
    assert!(
        verify_pseudorandom_zero_sharing_seed_delivery_320(
            &verified_root_terminal,
            sender_position,
            recipient_position,
            &vec![0_u8; 4_097],
            &entries,
        )
        .is_err()
    );

    let recipient_position = 5;
    let deliveries = verified_deliveries_for_recipient(
        &catalog_fixtures,
        &verified_root_terminal,
        recipient_position,
    );
    let recipient_inventory = verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
        &verified_root_terminal,
        recipient_position,
        deliveries,
    )
    .unwrap();
    assert_eq!(recipient_inventory.deliveries().len(), 9);
    assert_eq!(
        recipient_inventory.body().parameter_identity(),
        parameter_identity
    );
    assert_eq!(
        recipient_inventory.body().preparation_context_identity(),
        preparation_context.identity()
    );
    assert_eq!(
        recipient_inventory.body().root_terminal_identity(),
        verified_root_terminal.identity().unwrap()
    );
    assert_eq!(
        recipient_inventory.body().participant_count(),
        participant_count
    );
    assert_eq!(
        recipient_inventory.body().recipient_position(),
        recipient_position
    );
    assert_eq!(
        recipient_inventory.body().canonical_bytes().unwrap().len(),
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_INVENTORY_BODY_BYTE_LENGTH
    );
    let _ = recipient_inventory.body().identity().unwrap();
    assert!(format!("{recipient_inventory:?}").contains("[redacted]"));
    assert_eq!(recipient_inventory.into_deliveries().len(), 9);

    let mut reordered_deliveries = verified_deliveries_for_recipient(
        &catalog_fixtures,
        &verified_root_terminal,
        recipient_position,
    );
    reordered_deliveries.swap(0, 1);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
            &verified_root_terminal,
            recipient_position,
            reordered_deliveries,
        ),
        Err(PseudorandomZeroSharingSeedDeliveryError320::DeliveryOrder {
            delivery_index: 0,
            expected_sender_position: 0,
            actual_sender_position: 1,
        })
    ));
    let mut incomplete_deliveries = verified_deliveries_for_recipient(
        &catalog_fixtures,
        &verified_root_terminal,
        recipient_position,
    );
    incomplete_deliveries.pop();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_recipient_inventory_320(
            &verified_root_terminal,
            recipient_position,
            incomplete_deliveries,
        ),
        Err(PseudorandomZeroSharingSeedDeliveryError320::DeliveryCount {
            expected: 9,
            actual: 8,
        })
    ));
}

fn seed_catalog_fixture(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    marker: u8,
) -> SeedCatalogFixture320 {
    let mut commitment_digests = Vec::with_capacity(layout.leaf_count() as usize);
    let mut opening_bytes = Vec::with_capacity(layout.leaf_count() as usize);
    for (leaf_index, coordinate) in layout.coordinates().unwrap().enumerate() {
        let leaf_ordinal = leaf_index as u64;
        let salt = marked_bytes::<SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH>(
            marker.wrapping_add(0x11),
            leaf_ordinal,
        );
        match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(subset) => {
                let subset_coordinate = layout.subset_seed_coordinate(subset).unwrap();
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_subset_seed_contribution_320(
                        subset_coordinate,
                        marked_bytes::<
                            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
                        >(marker.wrapping_add(0x21), leaf_ordinal),
                        marked_bytes::<
                            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
                        >(marker.wrapping_add(0x31), leaf_ordinal),
                    )
                    .unwrap();
                commitment_digests.push(commitment.digest());
                opening_bytes.push(opening.canonical_bytes().unwrap());
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair {
                lower_roster_position,
                upper_roster_position,
            } => {
                let counterpart_position = if layout.contributor_position() == lower_roster_position
                {
                    upper_roster_position
                } else {
                    lower_roster_position
                };
                let pair_coordinate =
                    PseudorandomZeroSharingPairSeedContributionCoordinate320::from_catalog_layout(
                        layout,
                        counterpart_position,
                    )
                    .unwrap();
                let (commitment, opening) =
                    create_pseudorandom_zero_sharing_pair_seed_contribution_320(
                        pair_coordinate,
                        marked_bytes::<PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH>(
                            marker.wrapping_add(0x41),
                            leaf_ordinal,
                        ),
                        salt,
                    )
                    .unwrap();
                commitment_digests.push(commitment.digest());
                opening_bytes.push(opening.canonical_bytes().unwrap());
            }
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
                let coin_coordinate =
                    CollectiveCoinSourceCoordinate320::from_catalog_layout(layout).unwrap();
                let (commitment, opening) = create_collective_coin_source_320(
                    coin_coordinate,
                    marked_bytes::<COLLECTIVE_COIN_SOURCE_BYTE_LENGTH>(
                        marker.wrapping_add(0x51),
                        leaf_ordinal,
                    ),
                    salt,
                )
                .unwrap();
                commitment_digests.push(commitment.digest());
                opening_bytes.push(opening.canonical_bytes().unwrap());
            }
        }
    }
    SeedCatalogFixture320 {
        tree: PseudorandomZeroSharingSeedCatalogTree320::create(layout, commitment_digests)
            .unwrap(),
        opening_bytes: opening_bytes.into_boxed_slice(),
    }
}

fn seed_delivery_entries(
    fixture: &SeedCatalogFixture320,
    recipient_position: u16,
) -> Vec<OwnedSeedDeliveryEntry320> {
    let catalog_layout = fixture.tree.root_body().layout();
    let delivery_layout =
        PseudorandomZeroSharingSeedDeliveryLayout320::derive(catalog_layout, recipient_position)
            .unwrap();
    let mut coordinates = delivery_layout
        .subsets()
        .iter()
        .copied()
        .map(PseudorandomZeroSharingSeedCatalogCoordinate320::Subset)
        .collect::<Vec<_>>();
    coordinates.push(catalog_layout.pair_coordinate(recipient_position).unwrap());
    coordinates
        .into_iter()
        .map(|coordinate| {
            let leaf_ordinal = catalog_layout.leaf_ordinal(coordinate).unwrap();
            OwnedSeedDeliveryEntry320 {
                opening_bytes: Zeroizing::new(
                    fixture.opening_bytes[usize::try_from(leaf_ordinal).unwrap()].to_vec(),
                ),
                inclusion_proof_bytes: fixture
                    .tree
                    .inclusion_proof(leaf_ordinal)
                    .unwrap()
                    .canonical_bytes()
                    .unwrap(),
            }
        })
        .collect()
}

fn borrowed_delivery_entries(
    entries: &[OwnedSeedDeliveryEntry320],
) -> Vec<PseudorandomZeroSharingSeedDeliveryEntryBytes320<'_>> {
    entries
        .iter()
        .map(OwnedSeedDeliveryEntry320::borrowed)
        .collect()
}

fn verified_deliveries_for_recipient(
    fixtures: &[SeedCatalogFixture320],
    root_terminal: &RosterEndorsedPseudorandomZeroSharingSeedCatalogRootTerminal320,
    recipient_position: u16,
) -> Vec<RootInventoryMatchedPseudorandomZeroSharingSeedDelivery320> {
    (0..root_terminal.root_inventory().body().participant_count())
        .filter(|sender_position| *sender_position != recipient_position)
        .map(|sender_position| {
            let descriptor = derive_pseudorandom_zero_sharing_seed_delivery_descriptor_320(
                root_terminal,
                sender_position,
                recipient_position,
            )
            .unwrap();
            let owned_entries =
                seed_delivery_entries(&fixtures[usize::from(sender_position)], recipient_position);
            verify_pseudorandom_zero_sharing_seed_delivery_320(
                root_terminal,
                sender_position,
                recipient_position,
                &descriptor.canonical_bytes().unwrap(),
                &borrowed_delivery_entries(&owned_entries),
            )
            .unwrap()
        })
        .collect()
}

fn marked_bytes<const BYTE_LENGTH: usize>(marker: u8, ordinal: u64) -> [u8; BYTE_LENGTH] {
    let mut bytes = [marker; BYTE_LENGTH];
    let ordinal_bytes = ordinal.to_le_bytes();
    let copied_byte_length = BYTE_LENGTH.min(ordinal_bytes.len());
    bytes[..copied_byte_length].copy_from_slice(&ordinal_bytes[..copied_byte_length]);
    bytes
}

fn signed_root_terminal_certificate(
    root_inventory: &VerifiedPseudorandomZeroSharingSeedCatalogRootInventory320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    signature_seed_marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320 {
    let terminal_body =
        PseudorandomZeroSharingSeedCatalogRootTerminalBody320::new(root_inventory).unwrap();
    PseudorandomZeroSharingSeedCatalogRootTerminalCertificate320::new(
        terminal_body,
        signed_root_terminal_endorsement_envelopes(
            terminal_body,
            signing_keys,
            signature_seed_marker,
        ),
    )
    .unwrap()
}

fn signed_root_terminal_endorsement_envelopes(
    terminal_body: PseudorandomZeroSharingSeedCatalogRootTerminalBody320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    signature_seed_marker: u8,
) -> Vec<PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320> {
    (0..terminal_body.participant_count())
        .map(|endorser_position| {
            let authorization_body =
                PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementAuthorizationBody320::new(
                    terminal_body,
                    endorser_position,
                )
                .unwrap();
            let signature = signing_keys[usize::from(endorser_position)]
                .try_sign_with_seed(
                    &[signature_seed_marker.wrapping_add(endorser_position as u8); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_TERMINAL_SIGNATURE_CONTEXT,
                )
                .unwrap();
            PseudorandomZeroSharingSeedCatalogRootTerminalEndorsementEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect()
}

fn root_authorization_packages(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    roster: &Roster,
    signing_keys: &[ml_dsa_65::PrivateKey],
    root_marker: u8,
    alternate_authorization: bool,
) -> Vec<OwnedRootAuthorizationPackage320> {
    (0..preparation_context.participant_count())
        .map(|contributor_position| {
            root_authorization_package(
                parameter_identity,
                preparation_context,
                roster,
                signing_keys,
                contributor_position,
                root_marker.wrapping_add(contributor_position as u8),
                alternate_authorization,
            )
        })
        .collect()
}

fn root_authorization_package(
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    roster: &Roster,
    signing_keys: &[ml_dsa_65::PrivateKey],
    contributor_position: u16,
    contributor_root_marker: u8,
    alternate_authorization: bool,
) -> OwnedRootAuthorizationPackage320 {
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        parameter_identity,
        preparation_context,
        contributor_position,
    )
    .unwrap();
    let root_body = catalog_root(layout, contributor_root_marker);
    authorize_root_body(
        root_body,
        roster,
        signing_keys,
        contributor_root_marker,
        alternate_authorization,
    )
}

fn authorize_root_body(
    root_body: PseudorandomZeroSharingSeedCatalogRootBody320,
    roster: &Roster,
    signing_keys: &[ml_dsa_65::PrivateKey],
    contributor_root_marker: u8,
    alternate_authorization: bool,
) -> OwnedRootAuthorizationPackage320 {
    let layout = root_body.layout();
    let contributor_position = layout.contributor_position();
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let witness_positions = canonical_witness_positions(
        layout.participant_count(),
        contributor_position,
        alternate_authorization,
    );
    let reservation_intent =
        PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320::new(root_body).unwrap();
    let reservation_certificate = signed_reservation_certificate(
        reservation_intent,
        signing_keys,
        &witness_positions,
        contributor_root_marker.wrapping_add(if alternate_authorization { 0x21 } else { 0x11 }),
    );
    let reservation_certificate_bytes = reservation_certificate.canonical_bytes().unwrap();
    let verified_reservation =
        verify_pseudorandom_zero_sharing_seed_catalog_root_state_reservation_320(
            layout,
            &root_body_bytes,
            roster,
            &reservation_certificate_bytes,
        )
        .unwrap();
    let exact_output_intent =
        PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320::new(verified_reservation)
            .unwrap();
    let exact_output_certificate = signed_exact_output_certificate(
        exact_output_intent,
        signing_keys,
        &witness_positions,
        contributor_root_marker.wrapping_add(if alternate_authorization { 0x41 } else { 0x31 }),
    );
    let exact_output_certificate_bytes = exact_output_certificate.canonical_bytes().unwrap();
    let contributor_signature_body = PseudorandomZeroSharingSeedCatalogRootSignatureBody320::new(
        root_body,
        exact_output_certificate.identity().unwrap(),
    )
    .unwrap();
    let contributor_signature = signing_keys[usize::from(contributor_position)]
        .try_sign_with_seed(
            &[contributor_root_marker; 32],
            &contributor_signature_body.canonical_bytes().unwrap(),
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    let contributor_signature_envelope_bytes =
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(
            contributor_signature_body,
            contributor_signature,
        )
        .canonical_bytes()
        .unwrap();
    OwnedRootAuthorizationPackage320 {
        root_body_bytes,
        reservation_certificate_bytes,
        exact_output_certificate_bytes,
        contributor_signature_envelope_bytes,
    }
}

fn signed_reservation_certificate(
    reservation_intent: PseudorandomZeroSharingSeedCatalogRootStateReservationIntent320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    witness_positions: &[u16],
    seed_marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320 {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            let authorization_body =
                PseudorandomZeroSharingSeedCatalogRootStateWitnessAuthorizationBody320::new(
                    reservation_intent,
                    *witness_position,
                )
                .unwrap();
            let signature = signing_keys[usize::from(*witness_position)]
                .try_sign_with_seed(
                    &[seed_marker.wrapping_add(*witness_position as u8); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_STATE_WITNESS_SIGNATURE_CONTEXT,
                )
                .unwrap();
            PseudorandomZeroSharingSeedCatalogRootStateWitnessEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect();
    PseudorandomZeroSharingSeedCatalogRootStateReservationCertificate320::new(
        reservation_intent,
        witness_envelopes,
    )
    .unwrap()
}

fn signed_exact_output_certificate(
    exact_output_intent: PseudorandomZeroSharingSeedCatalogRootStateOutputIntent320,
    signing_keys: &[ml_dsa_65::PrivateKey],
    witness_positions: &[u16],
    seed_marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320 {
    let witness_envelopes = witness_positions
        .iter()
        .map(|witness_position| {
            let authorization_body =
                PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessAuthorizationBody320::new(
                    exact_output_intent,
                    *witness_position,
                )
                .unwrap();
            let signature = signing_keys[usize::from(*witness_position)]
                .try_sign_with_seed(
                    &[seed_marker.wrapping_add(*witness_position as u8); 32],
                    &authorization_body.canonical_bytes().unwrap(),
                    PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_EXACT_OUTPUT_WITNESS_SIGNATURE_CONTEXT,
                )
                .unwrap();
            PseudorandomZeroSharingSeedCatalogRootStateOutputWitnessEnvelope320::new(
                authorization_body,
                signature,
            )
        })
        .collect();
    PseudorandomZeroSharingSeedCatalogRootStateOutputCertificate320::new(
        exact_output_intent,
        witness_envelopes,
    )
    .unwrap()
}

fn canonical_witness_positions(
    participant_count: u16,
    contributor_position: u16,
    take_from_end: bool,
) -> Vec<u16> {
    let positions = (0..participant_count)
        .filter(|position| *position != contributor_position)
        .collect::<Vec<_>>();
    let witness_count = usize::from(
        derive_foundation_roster_parameters(participant_count)
            .unwrap()
            .state_witness_quorum,
    );
    if take_from_end {
        positions[positions.len() - witness_count..].to_vec()
    } else {
        positions[..witness_count].to_vec()
    }
}

fn catalog_root(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    marker: u8,
) -> PseudorandomZeroSharingSeedCatalogRootBody320 {
    PseudorandomZeroSharingSeedCatalogTree320::create(
        layout,
        (0..layout.leaf_count())
            .map(|leaf_ordinal| deterministic_hash(marker, leaf_ordinal))
            .collect(),
    )
    .unwrap()
    .root_body()
}

fn borrowed_packages(
    owned_packages: &[OwnedRootAuthorizationPackage320],
) -> Vec<PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320<'_>> {
    owned_packages
        .iter()
        .map(OwnedRootAuthorizationPackage320::borrowed)
        .collect()
}

fn roster_and_signing_keys(
    participant_count: u16,
    marker: u8,
) -> (Roster, Vec<ml_dsa_65::PrivateKey>) {
    let (roster, signing_keys, _) = roster_signing_and_mailbox_keys(participant_count, marker);
    (roster, signing_keys)
}

fn roster_signing_and_mailbox_keys(
    participant_count: u16,
    marker: u8,
) -> (
    Roster,
    Vec<ml_dsa_65::PrivateKey>,
    Vec<ml_kem_768::DecapsKey>,
) {
    let mut signing_keys = Vec::with_capacity(usize::from(participant_count));
    let mut mailbox_decapsulation_keys = Vec::with_capacity(usize::from(participant_count));
    let entries = (0..participant_count)
        .map(|roster_position| {
            let mut signing_seed = [marker; 32];
            signing_seed[0] = marker.wrapping_add(roster_position as u8);
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= roster_position as u8;
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= roster_position as u8;
            let (mailbox_encapsulation_key, mailbox_decapsulation_key) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            mailbox_decapsulation_keys.push(mailbox_decapsulation_key);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    (
        Roster::new(entries).unwrap(),
        signing_keys,
        mailbox_decapsulation_keys,
    )
}

fn build_preparation_context(roster: &Roster, attempt_marker: u8) -> TallyPreparationContext {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            u16::try_from(roster.entries.len()).unwrap(),
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    TallyPreparationContext::new(
        deterministic_hash(0xe1, 0),
        roster.roster_hash().unwrap(),
        [attempt_marker; 32],
        &circuit,
    )
    .unwrap()
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}
