use std::collections::BTreeSet;

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
        CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, FOUNDATION_PROFILE, Hash512, Roster,
        RosterEntry,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    collective_coin_source_bivariate_commitment_320::{
        AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        CollectiveCoinSourceBivariateCommitmentCoordinate320,
        CollectiveCoinSourceBivariateCommitmentError320,
        CollectiveCoinSourceBivariateCommitmentInventory320,
        CollectiveCoinSourceBivariateCommitmentLayout320,
        CollectiveCoinSourceBivariateCommitmentRootBody320,
        CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320,
        collective_coin_source_bivariate_private_row_body_byte_length,
        derive_collective_coin_source_bivariate_commitment_digest_320,
        verify_collective_coin_source_bivariate_commitment_root_signature_320,
        verify_collective_coin_source_bivariate_private_row_320,
    },
    collective_coin_source_bivariate_sharing_320::{
        CollectiveCoinSourceBivariateReleaseDecoder320,
        CollectiveCoinSourceBivariateReleaseDecoding320, CollectiveCoinSourceComponent320,
        CollectiveCoinSourceSymmetricBivariatePolynomial320,
    },
    pseudorandom_zero_sharing_seed_master_join_320_tests::completion_joined_seed_masters_and_fixture_for_test,
};

const COMPLETION_ROOT_BODY_BYTE_LENGTH: usize = 12_098;
const COMPLETION_SIGNATURE_ENVELOPE_BYTE_LENGTH: usize = 3_488;
const COMPLETION_PRIVATE_ROW_BODY_BYTE_LENGTH: usize = 3_388;

#[test]
fn joined_source_and_salt_cross_the_signed_root_and_every_authenticated_row_exactly() {
    let fixture = joined_completion_fixture();
    let authenticated_root = authenticate_root(&fixture, 0x31);
    let decoder = CollectiveCoinSourceBivariateReleaseDecoder320::new(
        fixture.layout.participant_count(),
        fixture.layout.contributor_position(),
    )
    .unwrap();
    assert_eq!(decoder.minimum_consistent_row_count(), 7);
    assert_eq!(decoder.committed_field_value_count(), 165);
    assert_eq!(decoder.field_values_per_holder(), 30);

    let mut authenticated_rows = Vec::new();
    for holder_position in 0..fixture.layout.participant_count() {
        let private_row_body_bytes = fixture
            .inventory
            .private_row_body(holder_position)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let authenticated_row = verify_collective_coin_source_bivariate_private_row_320(
            &authenticated_root,
            &private_row_body_bytes,
        )
        .unwrap();
        assert_eq!(
            authenticated_row.root_body_identity(),
            authenticated_root.root_body_identity()
        );
        assert_eq!(
            authenticated_row.contributor_position(),
            fixture.layout.contributor_position()
        );
        assert_eq!(authenticated_row.holder_position(), holder_position);
        assert_eq!(
            authenticated_row.row(),
            &fixture.polynomial.row(holder_position).unwrap()
        );
        assert_eq!(
            authenticated_row
                .private_row_body_bytes()
                .unwrap()
                .as_slice(),
            private_row_body_bytes.as_slice()
        );
        authenticated_rows.push(authenticated_row);
    }

    let released_rows = authenticated_rows
        .iter()
        .take(decoder.minimum_consistent_row_count())
        .map(|authenticated_row| authenticated_row.row().clone())
        .collect::<Vec<_>>();
    let CollectiveCoinSourceBivariateReleaseDecoding320::Decoded(decoded) =
        decoder.decode(&released_rows).unwrap()
    else {
        panic!("seven authenticated completion rows must reconstruct")
    };
    assert_eq!(decoded.source(), &fixture.expected_source);
    assert_eq!(decoded.commitment_salt(), &fixture.expected_commitment_salt);
    assert_eq!(
        decoded.supporting_holder_positions(),
        &[0, 1, 2, 3, 4, 5, 6]
    );
}

#[test]
fn completion_layout_has_one_canonical_leaf_for_every_shared_field_value() {
    let fixture = synthetic_completion_fixture(0x31);
    let layout = fixture.layout;
    assert_eq!(
        layout.participant_count(),
        FOUNDATION_PROFILE.participant_count
    );
    assert_eq!(layout.reconstruction_threshold(), 4);
    assert_eq!(layout.secret_axis_leaf_count_per_component(), 10);
    assert_eq!(layout.crosspoint_leaf_count_per_component(), 45);
    assert_eq!(layout.leaf_count_per_component(), 55);
    assert_eq!(layout.leaf_count(), 165);

    let coordinates = layout.coordinates().unwrap();
    assert_eq!(coordinates.len(), 165);
    assert_eq!(
        coordinates.iter().copied().collect::<BTreeSet<_>>().len(),
        165
    );
    for (expected_leaf_ordinal, coordinate) in coordinates.iter().copied().enumerate() {
        assert_eq!(
            layout.leaf_ordinal(coordinate).unwrap(),
            u64::try_from(expected_leaf_ordinal).unwrap()
        );
    }
    for holder_position in 0..layout.participant_count() {
        let holder_coordinates = layout.holder_coordinates(holder_position).unwrap();
        assert_eq!(holder_coordinates.len(), 30);
        assert_eq!(
            holder_coordinates
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            30
        );
        for component in CollectiveCoinSourceComponent320::ALL {
            assert!(holder_coordinates.contains(
                &CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
                    component,
                    holder_position,
                }
            ));
            for peer_holder_position in 0..layout.participant_count() {
                if peer_holder_position == holder_position {
                    continue;
                }
                assert!(holder_coordinates.contains(
                    &CollectiveCoinSourceBivariateCommitmentCoordinate320::Crosspoint {
                        component,
                        lower_holder_position: holder_position.min(peer_holder_position),
                        upper_holder_position: holder_position.max(peer_holder_position),
                    }
                ));
            }
        }
    }

    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(layout.contributor_position())],
        0x41,
    );
    let private_row_body_bytes = fixture
        .inventory
        .private_row_body(0)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    assert_eq!(root_body_bytes.len(), COMPLETION_ROOT_BODY_BYTE_LENGTH);
    assert_eq!(
        signature_envelope_bytes.len(),
        COMPLETION_SIGNATURE_ENVELOPE_BYTE_LENGTH
    );
    assert_eq!(
        private_row_body_bytes.len(),
        COMPLETION_PRIVATE_ROW_BODY_BYTE_LENGTH
    );
    assert_eq!(
        collective_coin_source_bivariate_private_row_body_byte_length(layout.participant_count())
            .unwrap(),
        private_row_body_bytes.len()
    );
}

#[test]
fn wrong_signatures_and_changed_openings_never_authenticate_collective_coin_custody() {
    let fixture = synthetic_completion_fixture(0x41);
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x51,
    );
    let authenticated_root = verify_collective_coin_source_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &signature_envelope_bytes,
    )
    .unwrap();

    let wrong_signer_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position() + 1)],
        0x61,
    );
    assert_eq!(
        verify_collective_coin_source_bivariate_commitment_root_signature_320(
            fixture.layout,
            &root_body_bytes,
            &fixture.roster,
            &wrong_signer_envelope_bytes,
        ),
        Err(CollectiveCoinSourceBivariateCommitmentError320::InvalidSignature)
    );

    let mut changed_root_tuple = decode_tuple(&root_body_bytes);
    let first_digest_position = 16;
    let mut changed_digest = changed_root_tuple.items[first_digest_position]
        .canonical_bytes()
        .to_vec();
    changed_digest[0] ^= 0x80;
    changed_root_tuple.items[first_digest_position] =
        CanonicalItem::hash512(changed_digest.try_into().unwrap());
    assert_eq!(
        verify_collective_coin_source_bivariate_commitment_root_signature_320(
            fixture.layout,
            &changed_root_tuple.encode().unwrap(),
            &fixture.roster,
            &signature_envelope_bytes,
        ),
        Err(
            CollectiveCoinSourceBivariateCommitmentError320::ObjectMismatch {
                field: "root-body identity"
            }
        )
    );

    let private_row_body_bytes = fixture
        .inventory
        .private_row_body(0)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    for changed_payload_position in [0, BinaryFieldElement320::CANONICAL_BYTE_LENGTH] {
        let mut changed_row_tuple = decode_tuple(&private_row_body_bytes);
        let mut changed_payload = changed_row_tuple.items[7].canonical_bytes().to_vec();
        changed_payload[changed_payload_position] ^= 0x80;
        changed_row_tuple.items[7] = CanonicalItem::fixed_bytes(changed_payload).unwrap();
        assert!(matches!(
            verify_collective_coin_source_bivariate_private_row_320(
                &authenticated_root,
                &changed_row_tuple.encode().unwrap(),
            ),
            Err(
                CollectiveCoinSourceBivariateCommitmentError320::CommitmentMismatch {
                    leaf_ordinal: 0
                }
            )
        ));
    }

    let mut truncated_row_tuple = decode_tuple(&private_row_body_bytes);
    let mut truncated_payload = truncated_row_tuple.items[7].canonical_bytes().to_vec();
    truncated_payload.pop();
    truncated_row_tuple.items[7] = CanonicalItem::fixed_bytes(truncated_payload).unwrap();
    assert_eq!(
        verify_collective_coin_source_bivariate_private_row_320(
            &authenticated_root,
            &truncated_row_tuple.encode().unwrap(),
        ),
        Err(
            CollectiveCoinSourceBivariateCommitmentError320::PrivateRowPayloadByteLength {
                expected: 3_120,
                actual: 3_119,
            }
        )
    );
}

#[test]
fn root_consistent_but_nonpolynomial_private_rows_are_rejected() {
    let fixture = synthetic_completion_fixture(0x51);
    let original_private_row_body_bytes = fixture
        .inventory
        .private_row_body(0)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut changed_row_tuple = decode_tuple(&original_private_row_body_bytes);
    let mut changed_payload = changed_row_tuple.items[7].canonical_bytes().to_vec();
    changed_payload[0] ^= 0x01;
    let changed_value = BinaryFieldElement320::from_canonical_bytes(
        &changed_payload[..BinaryFieldElement320::CANONICAL_BYTE_LENGTH],
    )
    .unwrap();
    let changed_salt = changed_payload[BinaryFieldElement320::CANONICAL_BYTE_LENGTH
        ..BinaryFieldElement320::CANONICAL_BYTE_LENGTH
            + COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]
        .try_into()
        .unwrap();
    let changed_coordinate = CollectiveCoinSourceBivariateCommitmentCoordinate320::SecretAxis {
        component: CollectiveCoinSourceComponent320::Source,
        holder_position: 0,
    };
    let changed_leaf_ordinal = fixture.layout.leaf_ordinal(changed_coordinate).unwrap();
    assert_eq!(changed_leaf_ordinal, 0);

    let mut changed_commitment_digests =
        fixture.inventory.root_body().commitment_digests().to_vec();
    changed_commitment_digests[usize::try_from(changed_leaf_ordinal).unwrap()] =
        derive_collective_coin_source_bivariate_commitment_digest_320(
            fixture.layout,
            changed_coordinate,
            changed_value,
            changed_salt,
        )
        .unwrap();
    let changed_root_body = CollectiveCoinSourceBivariateCommitmentRootBody320::new(
        fixture.layout,
        changed_commitment_digests,
    )
    .unwrap();
    let changed_root_body_bytes = changed_root_body.canonical_bytes().unwrap();
    let changed_signature_envelope_bytes = sign_root(
        &changed_root_body,
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        0x71,
    );
    let changed_authenticated_root =
        verify_collective_coin_source_bivariate_commitment_root_signature_320(
            fixture.layout,
            &changed_root_body_bytes,
            &fixture.roster,
            &changed_signature_envelope_bytes,
        )
        .unwrap();
    changed_row_tuple.items[2] =
        CanonicalItem::hash512(changed_root_body.identity().unwrap().into_bytes());
    changed_row_tuple.items[7] = CanonicalItem::fixed_bytes(changed_payload).unwrap();

    assert_eq!(
        verify_collective_coin_source_bivariate_private_row_320(
            &changed_authenticated_root,
            &changed_row_tuple.encode().unwrap(),
        ),
        Err(
            CollectiveCoinSourceBivariateCommitmentError320::LocalRowDegreeMismatch {
                holder_position: 0,
                component: CollectiveCoinSourceComponent320::Source,
            }
        )
    );
}

#[test]
fn retained_source_material_is_redacted_from_debug_output() {
    let fixture = synthetic_completion_fixture(0x61);
    let authenticated_root = authenticate_root(&fixture, 0x81);
    let private_row_body_bytes = fixture
        .inventory
        .private_row_body(0)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let authenticated_row = verify_collective_coin_source_bivariate_private_row_320(
        &authenticated_root,
        &private_row_body_bytes,
    )
    .unwrap();
    let inventory_debug = format!("{:?}", fixture.inventory);
    let row_debug = format!("{authenticated_row:?}");
    assert!(inventory_debug.contains("[redacted]"));
    assert!(row_debug.contains("[redacted]"));
    assert!(!inventory_debug.contains(&hex_prefix(&fixture.expected_source)));
    assert!(!row_debug.contains(&hex_prefix(&fixture.expected_source)));
}

pub(super) struct CompletionFixture {
    pub(super) roster: Roster,
    pub(super) signing_keys: Vec<ml_dsa_65::PrivateKey>,
    pub(super) mailbox_decapsulation_keys: Vec<ml_kem_768::DecapsKey>,
    pub(super) layout: CollectiveCoinSourceBivariateCommitmentLayout320,
    pub(super) polynomial: CollectiveCoinSourceSymmetricBivariatePolynomial320,
    pub(super) inventory: CollectiveCoinSourceBivariateCommitmentInventory320,
    pub(super) expected_source: [u8; 40],
    pub(super) expected_commitment_salt: [u8; 64],
}

fn joined_completion_fixture() -> CompletionFixture {
    let (joined_seed_masters, owner) = completion_joined_seed_masters_and_fixture_for_test();
    let expected_source = *joined_seed_masters.collective_coin_source().source();
    let expected_commitment_salt = *joined_seed_masters
        .collective_coin_source()
        .commitment_salt();
    let layout = CollectiveCoinSourceBivariateCommitmentLayout320::from_joined_seed_masters(
        &joined_seed_masters,
    )
    .unwrap();
    let polynomial = CollectiveCoinSourceSymmetricBivariatePolynomial320::
        from_joined_seed_masters_and_random_coefficients(
            &joined_seed_masters,
            deterministic_random_coefficients(layout.participant_count(), 0x11),
        )
        .unwrap();
    let inventory = CollectiveCoinSourceBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_commitment_salts(layout.leaf_count(), 0x21),
    )
    .unwrap();
    CompletionFixture {
        roster: owner.roster,
        signing_keys: owner.signing_keys,
        mailbox_decapsulation_keys: owner.mailbox_decapsulation_keys,
        layout,
        polynomial,
        inventory,
        expected_source,
        expected_commitment_salt,
    }
}

pub(super) fn synthetic_completion_fixture(marker: u8) -> CompletionFixture {
    let (roster, signing_keys, mailbox_decapsulation_keys) =
        completion_roster_signing_and_mailbox_keys(marker);
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    let preparation_context = TallyPreparationContext::new(
        deterministic_hash(marker.wrapping_add(1), 0),
        roster.roster_hash().unwrap(),
        [marker.wrapping_add(2); 32],
        &circuit,
    )
    .unwrap();
    let layout = CollectiveCoinSourceBivariateCommitmentLayout320::derive(
        deterministic_hash(marker.wrapping_add(3), 0),
        preparation_context,
        deterministic_hash(marker.wrapping_add(4), 0),
        deterministic_hash(marker.wrapping_add(5), 0),
        0,
    )
    .unwrap();
    let expected_source = deterministic_secret::<40>(marker.wrapping_add(6));
    let expected_commitment_salt = deterministic_secret::<64>(marker.wrapping_add(7));
    let polynomial =
        CollectiveCoinSourceSymmetricBivariatePolynomial320::from_source_and_salt_for_test(
            layout.participant_count(),
            layout.contributor_position(),
            &expected_source,
            &expected_commitment_salt,
            &deterministic_random_coefficients(layout.participant_count(), marker.wrapping_add(8)),
        )
        .unwrap();
    let inventory = CollectiveCoinSourceBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_commitment_salts(layout.leaf_count(), marker.wrapping_add(9)),
    )
    .unwrap();
    CompletionFixture {
        roster,
        signing_keys,
        mailbox_decapsulation_keys,
        layout,
        polynomial,
        inventory,
        expected_source,
        expected_commitment_salt,
    }
}

fn deterministic_random_coefficients(
    participant_count: u16,
    marker: u8,
) -> Vec<BinaryFieldElement320> {
    let reconstruction_threshold = usize::from(
        crate::foundation::derive_foundation_roster_parameters(participant_count)
            .unwrap()
            .reconstruction_threshold,
    );
    let coefficient_count_per_component =
        reconstruction_threshold * (reconstruction_threshold + 1) / 2 - 1;
    (0..coefficient_count_per_component * CollectiveCoinSourceComponent320::ALL.len())
        .map(|coefficient_position| {
            BinaryFieldElement320::from_low_polynomial_u16(
                u16::from(marker)
                    .wrapping_mul(257)
                    .wrapping_add(u16::try_from(coefficient_position + 1).unwrap()),
            )
        })
        .collect()
}

fn deterministic_commitment_salts(
    leaf_count: u64,
    marker: u8,
) -> Vec<[u8; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]> {
    (0..leaf_count)
        .map(|leaf_ordinal| {
            let mut salt = [marker; COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH];
            salt[..8].copy_from_slice(&leaf_ordinal.to_le_bytes());
            salt[63] ^= u8::try_from(leaf_ordinal % 251).unwrap();
            salt
        })
        .collect()
}

fn completion_roster_signing_and_mailbox_keys(
    marker: u8,
) -> (
    Roster,
    Vec<ml_dsa_65::PrivateKey>,
    Vec<ml_kem_768::DecapsKey>,
) {
    let mut signing_keys = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    let mut mailbox_decapsulation_keys =
        Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    let roster_entries = (0..FOUNDATION_PROFILE.participant_count)
        .map(|roster_position| {
            let roster_position_marker = u8::try_from(roster_position).unwrap();
            let mut signing_seed = [marker; 32];
            signing_seed[0] = marker.wrapping_add(roster_position_marker);
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= roster_position_marker;
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= roster_position_marker;
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
        Roster::new(roster_entries).unwrap(),
        signing_keys,
        mailbox_decapsulation_keys,
    )
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}

fn deterministic_secret<const BYTE_LENGTH: usize>(marker: u8) -> [u8; BYTE_LENGTH] {
    core::array::from_fn(|byte_position| {
        marker.wrapping_add(u8::try_from(byte_position % 251).unwrap())
    })
}

pub(super) fn authenticate_root(
    fixture: &CompletionFixture,
    signature_marker: u8,
) -> AuthorAuthenticatedCollectiveCoinSourceBivariateCommitmentRoot320 {
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.contributor_position())],
        signature_marker,
    );
    verify_collective_coin_source_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &signature_envelope_bytes,
    )
    .unwrap()
}

fn sign_root(
    root_body: &CollectiveCoinSourceBivariateCommitmentRootBody320,
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> Vec<u8> {
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_marker; 32],
            &root_body_bytes,
            COLLECTIVE_COIN_SOURCE_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    CollectiveCoinSourceBivariateCommitmentSignatureEnvelope320::new(
        root_body.identity().unwrap(),
        signature,
    )
    .canonical_bytes()
    .unwrap()
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
