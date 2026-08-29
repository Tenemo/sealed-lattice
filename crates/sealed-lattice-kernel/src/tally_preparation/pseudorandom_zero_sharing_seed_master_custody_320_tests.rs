use zeroize::Zeroizing;

use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    pseudorandom_zero_sharing_pair_and_coin_seed_320::{
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH, COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH,
    },
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogCoordinate320,
        PseudorandomZeroSharingSeedCatalogInclusionProof320,
        PseudorandomZeroSharingSeedCatalogLayout320,
    },
    pseudorandom_zero_sharing_seed_catalog_root_inventory_320_tests::{
        OwnedRootAuthorizationPackage320, SeedCatalogFixture320, SeedMailboxTestFixture320,
        authorize_root_body, seed_catalog_fixture, seed_delivery_payload_bytes,
        seed_mailbox_test_fixture_320, seed_mailbox_test_fixture_with_parameter_identity_320,
        signed_root_terminal_certificate,
    },
    pseudorandom_zero_sharing_seed_delivery_320::PseudorandomZeroSharingSeedDeliveryLayout320,
    pseudorandom_zero_sharing_seed_master_custody_320::{
        join_and_encode_for_test, restore_pseudorandom_zero_sharing_joined_seed_masters_320,
        run_pseudorandom_zero_sharing_joined_seed_master_restoration_validation_320,
        run_pseudorandom_zero_sharing_joined_seed_master_validation_320,
        run_pseudorandom_zero_sharing_seed_master_join_custody_320,
    },
    pseudorandom_zero_sharing_seed_receipt_320::RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    pseudorandom_zero_sharing_seed_receipt_terminal_320::{
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
        verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320,
    },
    pseudorandom_zero_sharing_seed_receipt_terminal_320_tests::{
        signed_receipt_envelopes_from_authenticated_deliveries, signed_terminal_certificate,
        verified_receipt_inventory,
    },
    pseudorandom_zero_sharing_subset_seed_320::{
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH,
    },
};

const CODEC_VERSION: u16 = 1;
const COMPLETED_RECORD_KIND: u8 = 2;
const PARTICIPANT_POSITION: u16 = 0;

struct CompletionCustodyFixture320 {
    action_context_identity: Hash512,
    authenticated_inventory_identity: Hash512,
    catalog_compiler_identity: Hash512,
    parameter_identity: Hash512,
    participant_count: u16,
    preparation_context_identity: Hash512,
    receipt_body_identity: Hash512,
    receipt_envelope_identity: Hash512,
    receipt_terminal_certificate_bytes: Vec<u8>,
    receipt_terminal_certificate_identity: Hash512,
    receipt_terminal_identity: Hash512,
    root_terminal_certificate_bytes: Vec<u8>,
    root_terminal_certificate_identity: Hash512,
    root_terminal_identity: Hash512,
    roster_identity: Hash512,
    state_predecessor_identity: Hash512,
    source_custody_record_bytes: Zeroizing<Vec<u8>>,
    receipt_custody_record_bytes: Zeroizing<Vec<u8>>,
    verification_context_bytes: Vec<u8>,
}

impl CompletionCustodyFixture320 {
    fn join_request_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"SLJQ");
        append_unsigned16(&mut bytes, CODEC_VERSION);
        self.append_joined_context(&mut bytes);
        append_bounded_bytes(&mut bytes, &self.source_custody_record_bytes);
        append_bounded_bytes(&mut bytes, &self.receipt_custody_record_bytes);
        append_bounded_bytes(&mut bytes, &self.verification_context_bytes);
        append_bounded_bytes(&mut bytes, &self.root_terminal_certificate_bytes);
        append_bounded_bytes(&mut bytes, &self.receipt_terminal_certificate_bytes);
        bytes
    }

    fn joined_record_bytes(&self, payload_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"SLJM");
        append_unsigned16(&mut bytes, CODEC_VERSION);
        self.append_joined_context(&mut bytes);
        append_unsigned32(&mut bytes, self.verification_context_bytes.len());
        append_unsigned32(&mut bytes, self.root_terminal_certificate_bytes.len());
        append_unsigned32(&mut bytes, self.receipt_terminal_certificate_bytes.len());
        append_unsigned32(&mut bytes, payload_bytes.len());
        bytes.extend_from_slice(&self.verification_context_bytes);
        bytes.extend_from_slice(&self.root_terminal_certificate_bytes);
        bytes.extend_from_slice(&self.receipt_terminal_certificate_bytes);
        bytes.extend_from_slice(payload_bytes);
        bytes
    }

    fn append_joined_context(&self, bytes: &mut Vec<u8>) {
        for identity in [
            self.parameter_identity,
            self.roster_identity,
            self.action_context_identity,
            self.preparation_context_identity,
            self.catalog_compiler_identity,
            self.state_predecessor_identity,
            self.root_terminal_identity,
            self.root_terminal_certificate_identity,
            self.receipt_terminal_identity,
            self.receipt_terminal_certificate_identity,
            self.authenticated_inventory_identity,
            self.receipt_body_identity,
            self.receipt_envelope_identity,
        ] {
            bytes.extend_from_slice(identity.as_bytes());
        }
        append_unsigned16(bytes, 0);
        append_unsigned16(bytes, self.participant_count);
        append_unsigned16(bytes, PARTICIPANT_POSITION);
    }
}

#[test]
fn completion_custody_boundary_reverifies_exact_predecessors_and_terminals() {
    let fixture = completion_custody_fixture();
    assert_eq!(
        (
            fixture.verification_context_bytes.len(),
            fixture.root_terminal_certificate_bytes.len(),
            fixture.receipt_terminal_certificate_bytes.len(),
            fixture.source_custody_record_bytes.len(),
            fixture.receipt_custody_record_bytes.len(),
        ),
        (623_110, 36_230, 36_340, 677_741, 569_411),
    );
    let request_bytes = fixture.join_request_bytes();
    assert_eq!(request_bytes.len(), 1_943_696);
    join_and_encode_for_test(&request_bytes).unwrap();
    let response = run_pseudorandom_zero_sharing_seed_master_join_custody_320(&request_bytes);
    let joined_payload = parse_join_response(&response).unwrap();
    assert_eq!(joined_payload.len(), 4_958);

    let joined_record = fixture.joined_record_bytes(joined_payload);
    assert_eq!(joined_record.len(), 701_498);
    let validation_response =
        run_pseudorandom_zero_sharing_joined_seed_master_validation_320(&joined_record);
    assert_eq!(validation_response.as_slice(), b"SLJR\x01\x00\x02");
    let restoration_response =
        run_pseudorandom_zero_sharing_joined_seed_master_restoration_validation_320(&joined_record);
    assert_eq!(restoration_response.as_slice(), b"SLJR\x01\x00\x02");

    let restored =
        restore_pseudorandom_zero_sharing_joined_seed_masters_320(&joined_record).unwrap();
    assert_eq!(restored.parameter_identity(), fixture.parameter_identity);
    assert_eq!(
        restored.preparation_context().identity(),
        fixture.preparation_context_identity
    );
    assert_eq!(
        restored.root_terminal_identity(),
        fixture.root_terminal_identity
    );
    assert_eq!(
        restored.root_terminal_certificate_identity(),
        fixture.root_terminal_certificate_identity
    );
    assert_eq!(
        restored.receipt_terminal_identity(),
        fixture.receipt_terminal_identity
    );
    assert_eq!(
        restored.receipt_terminal_certificate_identity(),
        fixture.receipt_terminal_certificate_identity
    );
    assert_eq!(
        restored.authenticated_recipient_inventory_identity(),
        fixture.authenticated_inventory_identity
    );
    assert_eq!(
        restored.receipt_body_identity(),
        fixture.receipt_body_identity
    );
    assert_eq!(
        restored.receipt_envelope_identity(),
        fixture.receipt_envelope_identity
    );
    assert_eq!(restored.participant_position(), PARTICIPANT_POSITION);
    assert_eq!(restored.subset_masters().len(), 84);
    assert_eq!(restored.pair_masters().len(), 9);
    assert_eq!(restored.retained_secret_byte_length().unwrap(), 3_824);
    let restored_layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        fixture.parameter_identity,
        restored.preparation_context(),
        PARTICIPANT_POSITION,
    )
    .unwrap();
    let collective_coin_leaf_ordinal = restored_layout
        .leaf_ordinal(PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin)
        .unwrap();
    let catalog_marker = 0x21_u8.wrapping_add(PARTICIPANT_POSITION as u8);
    assert_eq!(
        restored.collective_coin_source().commitment_salt(),
        &marked_bytes::<SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH>(
            catalog_marker.wrapping_add(0x11),
            collective_coin_leaf_ordinal,
        )
    );
    assert_eq!(
        restored.collective_coin_source().source(),
        &marked_bytes::<COLLECTIVE_COIN_SOURCE_BYTE_LENGTH>(
            catalog_marker.wrapping_add(0x51),
            collective_coin_leaf_ordinal,
        )
    );
    assert_eq!(
        restored.custody_payload_bytes().unwrap().as_slice(),
        joined_payload
    );
    assert!(!format!("{restored:?}").contains(&"21".repeat(40)));

    let mut wrong_joined_provenance = joined_record.to_vec();
    let payload_offset = wrong_joined_provenance.len() - joined_payload.len();
    wrong_joined_provenance[payload_offset + 100] ^= 1;
    assert_failure_code(
        &run_pseudorandom_zero_sharing_joined_seed_master_validation_320(&wrong_joined_provenance),
        7,
    );
    assert_failure_code(
        &run_pseudorandom_zero_sharing_joined_seed_master_restoration_validation_320(
            &wrong_joined_provenance,
        ),
        7,
    );
    assert!(
        restore_pseudorandom_zero_sharing_joined_seed_masters_320(&wrong_joined_provenance)
            .is_err()
    );
}

#[test]
fn custody_boundary_refuses_context_source_receipt_and_inventory_mutations() {
    let fixture = completion_custody_fixture();

    let mut wrong_context = fixture.join_request_bytes().to_vec();
    wrong_context[6] ^= 1;
    assert_failure_code(
        &run_pseudorandom_zero_sharing_seed_master_join_custody_320(&wrong_context),
        3,
    );

    let mut changed_source_fixture = fixture.join_request_bytes().to_vec();
    let source_record_offset = joined_request_source_record_offset();
    let source_record_length = read_unsigned32(&changed_source_fixture, source_record_offset);
    let last_source_byte = source_record_offset + 4 + source_record_length - 1;
    changed_source_fixture[last_source_byte] ^= 1;
    assert_failure_code(
        &run_pseudorandom_zero_sharing_seed_master_join_custody_320(&changed_source_fixture),
        5,
    );

    let mut changed_receipt_fixture = fixture.join_request_bytes().to_vec();
    let receipt_length_offset = source_record_offset + 4 + source_record_length;
    let receipt_record_length = read_unsigned32(&changed_receipt_fixture, receipt_length_offset);
    let last_receipt_byte = receipt_length_offset + 4 + receipt_record_length - 1;
    changed_receipt_fixture[last_receipt_byte] ^= 1;
    assert_failure_code(
        &run_pseudorandom_zero_sharing_seed_master_join_custody_320(&changed_receipt_fixture),
        6,
    );

    let mut trailing = fixture.join_request_bytes().to_vec();
    trailing.push(0);
    assert_failure_code(
        &run_pseudorandom_zero_sharing_seed_master_join_custody_320(&trailing),
        1,
    );
    assert_failure_code(
        &run_pseudorandom_zero_sharing_seed_master_join_custody_320(&trailing[..3]),
        1,
    );
}

fn completion_custody_fixture() -> CompletionCustodyFixture320 {
    let owner_fixture = seed_mailbox_test_fixture_320(1, PARTICIPANT_POSITION);
    let (receipt_envelopes, _alternate_receipt_envelopes, retained_receipt) =
        signed_receipt_envelopes_from_authenticated_deliveries(0x31, 0x41, 0x51);
    completion_custody_fixture_from_verified_receipts(
        &owner_fixture,
        receipt_envelopes,
        retained_receipt,
    )
}

fn completion_custody_fixture_from_verified_receipts(
    owner_fixture: &SeedMailboxTestFixture320,
    receipt_envelopes: Vec<Vec<u8>>,
    retained_receipt: RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
) -> CompletionCustodyFixture320 {
    let parameter_identity = owner_fixture
        .root_terminal
        .root_inventory()
        .body()
        .parameter_identity();
    let preparation_context = owner_fixture
        .root_terminal
        .root_inventory()
        .root_body(PARTICIPANT_POSITION)
        .unwrap()
        .layout()
        .preparation_context();
    let participant_count = preparation_context.participant_count();
    let roster_identity = owner_fixture.roster.roster_hash().unwrap();
    let catalog_fixtures = (0..participant_count)
        .map(|contributor_position| {
            let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
                parameter_identity,
                preparation_context,
                contributor_position,
            )
            .unwrap();
            let fixture =
                seed_catalog_fixture(layout, 0x21_u8.wrapping_add(contributor_position as u8));
            assert_eq!(
                fixture.tree.root_body(),
                owner_fixture
                    .root_terminal
                    .root_inventory()
                    .root_body(contributor_position)
                    .unwrap()
            );
            fixture
        })
        .collect::<Vec<_>>();
    let root_packages = catalog_fixtures
        .iter()
        .enumerate()
        .map(|(contributor_index, fixture)| {
            authorize_root_body(
                fixture.tree.root_body(),
                &owner_fixture.roster,
                &owner_fixture.signing_keys,
                0x41_u8.wrapping_add(contributor_index as u8),
                false,
            )
        })
        .collect::<Vec<_>>();
    let root_terminal_certificate = signed_root_terminal_certificate(
        owner_fixture.root_terminal.root_inventory(),
        &owner_fixture.signing_keys,
        0x61,
    );
    let root_terminal_certificate_bytes = root_terminal_certificate.canonical_bytes().unwrap();
    assert_eq!(
        root_terminal_certificate.identity().unwrap(),
        owner_fixture.root_terminal.certificate_identity()
    );

    let receipt_inventory = verified_receipt_inventory(owner_fixture, &receipt_envelopes);
    let receipt_terminal_certificate = signed_terminal_certificate(
        &receipt_inventory,
        &owner_fixture.signing_keys,
        0x61,
        PSEUDORANDOM_ZERO_SHARING_SEED_RECIPIENT_RECEIPT_TERMINAL_SIGNATURE_CONTEXT,
    );
    let receipt_terminal_certificate_bytes =
        receipt_terminal_certificate.canonical_bytes().unwrap();
    let receipt_terminal = verify_pseudorandom_zero_sharing_seed_recipient_receipt_terminal_320(
        owner_fixture.root_terminal.clone(),
        receipt_inventory,
        &owner_fixture.roster,
        &receipt_terminal_certificate_bytes,
    )
    .unwrap();
    let state_predecessor_identity = Hash512::from_bytes([0xa7; Hash512::BYTE_LENGTH]);
    let local_catalog_fixture = &catalog_fixtures[usize::from(PARTICIPANT_POSITION)];
    let source_custody_record_bytes = encode_source_custody_record(
        owner_fixture,
        local_catalog_fixture,
        state_predecessor_identity,
        PARTICIPANT_POSITION,
    );
    let receipt_custody_record_bytes =
        encode_receipt_custody_record(owner_fixture, &retained_receipt, &receipt_envelopes[0]);
    let verification_context_bytes = encode_verification_context(
        parameter_identity,
        preparation_context.canonical_bytes(),
        owner_fixture.roster.encode().unwrap(),
        &root_packages,
        &receipt_envelopes,
    );
    let receipt_body = retained_receipt.receipt_body();
    CompletionCustodyFixture320 {
        action_context_identity: preparation_context.action_context_hash(),
        authenticated_inventory_identity: receipt_body.authenticated_recipient_inventory_identity(),
        catalog_compiler_identity: local_catalog_fixture
            .tree
            .root_body()
            .layout()
            .compiler_identity(),
        parameter_identity,
        participant_count,
        preparation_context_identity: preparation_context.identity(),
        receipt_body_identity: receipt_body.identity().unwrap(),
        receipt_envelope_identity: retained_receipt.receipt_envelope_identity(),
        receipt_terminal_certificate_bytes,
        receipt_terminal_certificate_identity: receipt_terminal.certificate_identity(),
        receipt_terminal_identity: receipt_terminal.identity().unwrap(),
        root_terminal_certificate_bytes,
        root_terminal_certificate_identity: owner_fixture.root_terminal.certificate_identity(),
        root_terminal_identity: owner_fixture.root_terminal.identity().unwrap(),
        roster_identity,
        state_predecessor_identity,
        source_custody_record_bytes,
        receipt_custody_record_bytes,
        verification_context_bytes,
    }
}

fn encode_verification_context(
    parameter_identity: Hash512,
    preparation_context_bytes: Vec<u8>,
    roster_bytes: Vec<u8>,
    root_packages: &[OwnedRootAuthorizationPackage320],
    receipt_envelopes: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SLJV");
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.extend_from_slice(parameter_identity.as_bytes());
    append_bounded_bytes(&mut bytes, &preparation_context_bytes);
    append_bounded_bytes(&mut bytes, &roster_bytes);
    append_unsigned16(&mut bytes, root_packages.len() as u16);
    for package in root_packages {
        append_bounded_bytes(&mut bytes, &package.root_body_bytes);
        append_bounded_bytes(&mut bytes, &package.reservation_certificate_bytes);
        append_bounded_bytes(&mut bytes, &package.exact_output_certificate_bytes);
        append_bounded_bytes(&mut bytes, &package.contributor_signature_envelope_bytes);
    }
    append_unsigned16(&mut bytes, receipt_envelopes.len() as u16);
    for envelope in receipt_envelopes {
        append_bounded_bytes(&mut bytes, envelope);
    }
    bytes
}

pub(super) fn encode_source_custody_record(
    owner_fixture: &SeedMailboxTestFixture320,
    catalog_fixture: &SeedCatalogFixture320,
    state_predecessor_identity: Hash512,
    participant_position: u16,
) -> Zeroizing<Vec<u8>> {
    let root_body = catalog_fixture.tree.root_body();
    let layout = root_body.layout();
    let preparation_context = layout.preparation_context();
    let coordinates = layout.coordinates().unwrap().collect::<Vec<_>>();
    let inclusion_proof_byte_length =
        PseudorandomZeroSharingSeedCatalogInclusionProof320::canonical_byte_length_for_layout(
            layout,
        )
        .unwrap();
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let recipient_positions = (0..layout.participant_count())
        .filter(|position| *position != participant_position)
        .collect::<Vec<_>>();
    let delivery_payloads = recipient_positions
        .iter()
        .map(|recipient_position| {
            let payload = seed_delivery_payload_bytes(catalog_fixture, *recipient_position);
            let expected_byte_length =
                PseudorandomZeroSharingSeedDeliveryLayout320::derive(layout, *recipient_position)
                    .unwrap()
                    .payload_byte_length();
            assert_eq!(payload.len(), expected_byte_length);
            payload
        })
        .collect::<Vec<_>>();
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_CONTRIBUTION_BYTE_LENGTH
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        COLLECTIVE_COIN_SOURCE_BYTE_LENGTH
    );
    assert_eq!(
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        SEED_CATALOG_SECRET_LEAF_COMMITMENT_SALT_BYTE_LENGTH
    );

    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"SLCS");
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.push(COMPLETED_RECORD_KIND);
    for identity in [
        layout.parameter_identity(),
        owner_fixture.roster.roster_hash().unwrap(),
        preparation_context.action_context_hash(),
        preparation_context.identity(),
        layout.compiler_identity(),
        state_predecessor_identity,
    ] {
        bytes.extend_from_slice(identity.as_bytes());
    }
    append_unsigned16(&mut bytes, 0);
    append_unsigned16(&mut bytes, layout.participant_count());
    append_unsigned16(&mut bytes, participant_position);
    append_unsigned32(&mut bytes, coordinates.len());
    append_unsigned32(
        &mut bytes,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
    );
    append_unsigned32(
        &mut bytes,
        PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
    );
    append_unsigned32(&mut bytes, root_body_bytes.len());
    append_unsigned32(&mut bytes, inclusion_proof_byte_length);
    append_unsigned16(&mut bytes, recipient_positions.len() as u16);
    for coordinate in &coordinates {
        append_unsigned32(&mut bytes, test_opening_byte_length(*coordinate));
    }
    for payload in &delivery_payloads {
        append_unsigned32(&mut bytes, payload.len());
    }
    let catalog_marker = 0x21_u8.wrapping_add(participant_position as u8);
    for (leaf_ordinal, coordinate) in coordinates.iter().enumerate() {
        let leaf_ordinal = leaf_ordinal as u64;
        let (contribution_marker, salt_marker) = match coordinate {
            PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => (
                catalog_marker.wrapping_add(0x21),
                catalog_marker.wrapping_add(0x31),
            ),
            PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => (
                catalog_marker.wrapping_add(0x41),
                catalog_marker.wrapping_add(0x11),
            ),
            PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => (
                catalog_marker.wrapping_add(0x51),
                catalog_marker.wrapping_add(0x11),
            ),
        };
        bytes.extend_from_slice(&marked_bytes::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_CONTRIBUTION_BYTE_LENGTH,
        >(contribution_marker, leaf_ordinal));
        bytes.extend_from_slice(&marked_bytes::<
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_COMMITMENT_SALT_BYTE_LENGTH,
        >(salt_marker, leaf_ordinal));
    }
    bytes.extend_from_slice(layout.identity().as_bytes());
    bytes.extend_from_slice(&root_body_bytes);
    for (leaf_ordinal, opening_bytes) in catalog_fixture.opening_bytes.iter().enumerate() {
        assert_eq!(
            opening_bytes.len(),
            test_opening_byte_length(coordinates[leaf_ordinal])
        );
        bytes.extend_from_slice(opening_bytes);
        let inclusion_proof_bytes = catalog_fixture
            .tree
            .inclusion_proof(leaf_ordinal as u64)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert_eq!(inclusion_proof_bytes.len(), inclusion_proof_byte_length);
        bytes.extend_from_slice(&inclusion_proof_bytes);
    }
    append_unsigned16(&mut bytes, delivery_payloads.len() as u16);
    for payload in &delivery_payloads {
        bytes.extend_from_slice(payload);
    }
    bytes
}

pub(super) fn encode_receipt_custody_record(
    owner_fixture: &SeedMailboxTestFixture320,
    retained_receipt: &super::pseudorandom_zero_sharing_seed_receipt_320::RosterAuthenticatedPseudorandomZeroSharingSeedRecipientReceipt320,
    receipt_envelope_bytes: &[u8],
) -> Zeroizing<Vec<u8>> {
    let receipt_body = retained_receipt.receipt_body();
    let authenticated_inventory_body = retained_receipt.recipient_inventory().body();
    let authenticated_inventory_body_bytes =
        authenticated_inventory_body.canonical_bytes().unwrap();
    let receipt_intent_bytes = receipt_body.canonical_bytes().unwrap();
    let sender_positions = (0..FOUNDATION_PROFILE.participant_count)
        .filter(|position| *position != PARTICIPANT_POSITION)
        .collect::<Vec<_>>();
    let segments = sender_positions
        .iter()
        .map(|sender_position| {
            let fixture = seed_mailbox_test_fixture_with_parameter_identity_320(
                *sender_position,
                PARTICIPANT_POSITION,
                owner_fixture.parameter_identity,
            );
            assert_eq!(
                fixture.root_terminal.identity().unwrap(),
                owner_fixture.root_terminal.identity().unwrap()
            );
            fixture.payload_bytes
        })
        .collect::<Vec<_>>();
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.extend_from_slice(b"SLRC");
    append_unsigned16(&mut bytes, CODEC_VERSION);
    bytes.push(COMPLETED_RECORD_KIND);
    for identity in [
        receipt_body.parameter_identity(),
        receipt_body.preparation_context_identity(),
        receipt_body.root_terminal_identity(),
    ] {
        bytes.extend_from_slice(identity.as_bytes());
    }
    append_unsigned16(&mut bytes, 0);
    append_unsigned16(&mut bytes, receipt_body.participant_count());
    append_unsigned16(&mut bytes, receipt_body.recipient_position());
    bytes.extend_from_slice(authenticated_inventory_body.identity().unwrap().as_bytes());
    bytes.extend_from_slice(receipt_body.identity().unwrap().as_bytes());
    append_unsigned32(&mut bytes, authenticated_inventory_body_bytes.len());
    append_unsigned32(&mut bytes, receipt_intent_bytes.len());
    append_unsigned16(&mut bytes, segments.len() as u16);
    for segment in &segments {
        append_unsigned32(&mut bytes, segment.len());
    }
    bytes.extend_from_slice(&authenticated_inventory_body_bytes);
    bytes.extend_from_slice(&receipt_intent_bytes);
    for segment in &segments {
        bytes.extend_from_slice(segment);
    }
    append_unsigned32(&mut bytes, receipt_envelope_bytes.len());
    bytes.extend_from_slice(receipt_envelope_bytes);
    bytes
}

const fn test_opening_byte_length(
    coordinate: PseudorandomZeroSharingSeedCatalogCoordinate320,
) -> usize {
    match coordinate {
        PseudorandomZeroSharingSeedCatalogCoordinate320::Subset(_) => {
            PSEUDORANDOM_ZERO_SHARING_SUBSET_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::Pair { .. } => {
            PSEUDORANDOM_ZERO_SHARING_PAIR_SEED_OPENING_OBJECT_BYTE_LENGTH
        }
        PseudorandomZeroSharingSeedCatalogCoordinate320::CollectiveCoin => {
            COLLECTIVE_COIN_SOURCE_OPENING_OBJECT_BYTE_LENGTH
        }
    }
}

fn marked_bytes<const BYTE_LENGTH: usize>(marker: u8, ordinal: u64) -> [u8; BYTE_LENGTH] {
    let mut bytes = [marker; BYTE_LENGTH];
    let ordinal_bytes = ordinal.to_le_bytes();
    let copied_byte_length = BYTE_LENGTH.min(ordinal_bytes.len());
    bytes[..copied_byte_length].copy_from_slice(&ordinal_bytes[..copied_byte_length]);
    bytes
}

fn parse_join_response(response: &[u8]) -> Result<&[u8], u16> {
    assert!(response.len() >= 7);
    assert_eq!(&response[..4], b"SLJR");
    assert_eq!(u16::from_le_bytes(response[4..6].try_into().unwrap()), 1);
    match response[6] {
        0 => Err(u16::from_le_bytes(response[7..9].try_into().unwrap())),
        1 => {
            let payload_byte_length = read_unsigned32(response, 7);
            assert_eq!(response.len(), 11 + payload_byte_length);
            Ok(&response[11..])
        }
        status => panic!("unexpected join response status {status}"),
    }
}

fn assert_failure_code(response: &[u8], expected_code: u16) {
    assert_eq!(parse_join_response(response), Err(expected_code));
    assert_eq!(response.len(), 9);
}

const fn joined_request_source_record_offset() -> usize {
    4 + size_of::<u16>() + 13 * Hash512::BYTE_LENGTH + 3 * size_of::<u16>()
}

fn read_unsigned32(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn append_unsigned16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_unsigned32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}

fn append_bounded_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    append_unsigned32(bytes, value.len());
    bytes.extend_from_slice(value);
}
