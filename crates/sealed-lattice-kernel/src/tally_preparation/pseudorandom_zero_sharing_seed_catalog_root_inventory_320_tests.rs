use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as SignatureKeyGen, SerDes as SignatureSerDes, Signer},
};

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
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogRootBody320,
        PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_INVENTORY_BODY_DOMAIN,
        PseudorandomZeroSharingSeedCatalogRootAuthorizationPackageBytes320,
        PseudorandomZeroSharingSeedCatalogRootInventoryError,
        verify_pseudorandom_zero_sharing_seed_catalog_root_inventory_320,
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
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let witness_positions = canonical_witness_positions(
        preparation_context.participant_count(),
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
    let mut signing_keys = Vec::with_capacity(usize::from(participant_count));
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
            let (mailbox_encapsulation_key, _) =
                ml_kem_768::KG::keygen_from_seed(mailbox_seed, mailbox_fallback_seed);
            RosterEntry::new(
                roster_position,
                signing_verification_key.into_bytes(),
                mailbox_encapsulation_key.into_bytes(),
            )
            .unwrap()
        })
        .collect();
    (Roster::new(entries).unwrap(), signing_keys)
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
