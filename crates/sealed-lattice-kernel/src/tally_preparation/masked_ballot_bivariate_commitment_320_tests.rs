use std::collections::{BTreeSet, HashSet};

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
        RosterEntry, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    masked_ballot_bivariate_commitment_320::{
        AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH,
        MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        MaskedBallotBivariateCommitmentCoordinate320, MaskedBallotBivariateCommitmentError320,
        MaskedBallotBivariateCommitmentInventory320, MaskedBallotBivariateCommitmentLayout320,
        MaskedBallotBivariateCommitmentRootBody320,
        MaskedBallotBivariateCommitmentSignatureEnvelope320,
        derive_masked_ballot_bivariate_commitment_digest_320,
        verify_masked_ballot_bivariate_commitment_root_signature_320,
        verify_masked_ballot_bivariate_private_row_320,
    },
    masked_ballot_bivariate_sharing_320::{
        MaskedBallotBivariateReleaseDecoder320, MaskedBallotBivariateReleaseDecoding320,
        MaskedBallotSymmetricBivariatePolynomial320,
    },
    masked_ballot_bundle_320::{MaskedBallotBundle320, masked_ballot_bundle_input_bit_count},
};

#[test]
fn every_completion_holder_authenticates_one_root_bound_row_and_release_reconstructs() {
    let fixture = completion_fixture(0x21, 0x31);
    let authenticated_root = authenticate_root(
        fixture.layout,
        &fixture.inventory,
        &fixture.roster,
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x41,
    );
    let mut authenticated_rows = Vec::new();
    for holder_roster_position in 0..FOUNDATION_PROFILE.participant_count {
        let private_row_body = fixture
            .inventory
            .private_row_body(holder_roster_position)
            .unwrap();
        let private_row_body_bytes = private_row_body.canonical_bytes().unwrap();
        let authenticated_row = verify_masked_ballot_bivariate_private_row_320(
            &authenticated_root,
            &private_row_body_bytes,
        )
        .unwrap();
        assert_eq!(
            authenticated_row.root_body_identity(),
            authenticated_root.root_body_identity()
        );
        assert_eq!(
            authenticated_row.author_roster_position(),
            fixture.layout.author_roster_position()
        );
        assert_eq!(
            authenticated_row.holder_roster_position(),
            holder_roster_position
        );
        assert_eq!(
            authenticated_row.row(),
            &fixture.polynomial.row(holder_roster_position).unwrap()
        );
        authenticated_rows.push(authenticated_row);
    }

    let decoder =
        MaskedBallotBivariateReleaseDecoder320::new(FOUNDATION_PROFILE.participant_count).unwrap();
    let released_rows = authenticated_rows
        .iter()
        .take(decoder.minimum_consistent_row_count())
        .map(|authenticated_row| authenticated_row.row().clone())
        .collect::<Vec<_>>();
    let decoded = decoder.decode(&fixture.circuit, &released_rows).unwrap();
    let MaskedBallotBivariateReleaseDecoding320::Decoded(decoded) = decoded else {
        panic!("seven authenticated completion rows must decode")
    };
    assert_eq!(decoded.bundle(), &fixture.bundle);
}

#[test]
fn all_absent_and_present_bundles_have_identical_public_and_private_shapes() {
    let (roster, signing_keys) =
        roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, 0x51);
    let circuit = completion_circuit();
    let context = completion_context(&roster, &circuit, 0x61);
    let layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(0x71, 0),
        context,
        deterministic_hash(0x81, 0),
        4,
    )
    .unwrap();
    let all_absent_bundle = MaskedBallotBundle320::from_canonical_bytes(
        &circuit,
        &vec![0_u8; canonical_bundle_byte_length(&circuit)],
    )
    .unwrap();
    let present_bundle = patterned_bundle(&circuit, 0x91);
    let all_absent_polynomial = polynomial_for_bundle(layout, &all_absent_bundle, 0xa1);
    let present_polynomial = polynomial_for_bundle(layout, &present_bundle, 0xb1);
    let all_absent_inventory = MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &all_absent_polynomial,
        deterministic_salts(layout.leaf_count(), 0xc1),
    )
    .unwrap();
    let present_inventory = MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &present_polynomial,
        deterministic_salts(layout.leaf_count(), 0xd1),
    )
    .unwrap();

    let all_absent_root_body_bytes = all_absent_inventory.root_body().canonical_bytes().unwrap();
    let present_root_body_bytes = present_inventory.root_body().canonical_bytes().unwrap();
    assert_eq!(
        all_absent_root_body_bytes.len(),
        present_root_body_bytes.len()
    );
    assert_ne!(all_absent_root_body_bytes, present_root_body_bytes);

    let all_absent_signature_envelope_bytes =
        sign_root(all_absent_inventory.root_body(), &signing_keys[4], 0xe1);
    let present_signature_envelope_bytes =
        sign_root(present_inventory.root_body(), &signing_keys[4], 0xf1);
    assert_eq!(
        all_absent_signature_envelope_bytes.len(),
        present_signature_envelope_bytes.len()
    );

    for holder_roster_position in 0..FOUNDATION_PROFILE.participant_count {
        let all_absent_row_bytes = all_absent_inventory
            .private_row_body(holder_roster_position)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let present_row_bytes = present_inventory
            .private_row_body(holder_roster_position)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert_eq!(all_absent_row_bytes.len(), present_row_bytes.len());
        assert_ne!(all_absent_row_bytes, present_row_bytes);
    }

    // These exact completion lengths are protocol-owned framing evidence. They
    // do not include a future mailbox carrier, receipt, or state certificate.
    assert_eq!(all_absent_root_body_bytes.len(), 4_277);
    assert_eq!(all_absent_signature_envelope_bytes.len(), 3_467);
    assert_eq!(
        all_absent_inventory
            .private_row_body(0)
            .unwrap()
            .canonical_bytes()
            .unwrap()
            .len(),
        1_287
    );
}

#[test]
fn signed_root_and_private_row_mutations_never_create_authenticated_custody() {
    let fixture = completion_fixture(0x12, 0x22);
    let root_body_bytes = fixture.inventory.root_body().canonical_bytes().unwrap();
    let valid_signature_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x32,
    );
    let authenticated_root = verify_masked_ballot_bivariate_commitment_root_signature_320(
        fixture.layout,
        &root_body_bytes,
        &fixture.roster,
        &valid_signature_envelope_bytes,
    )
    .unwrap();

    let wrong_signer_envelope_bytes = sign_root(
        fixture.inventory.root_body(),
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position() + 1)],
        0x42,
    );
    assert_eq!(
        verify_masked_ballot_bivariate_commitment_root_signature_320(
            fixture.layout,
            &root_body_bytes,
            &fixture.roster,
            &wrong_signer_envelope_bytes,
        ),
        Err(MaskedBallotBivariateCommitmentError320::InvalidSignature)
    );

    let mut changed_signature_envelope_tuple = decode_tuple(&valid_signature_envelope_bytes);
    let mut changed_signature = changed_signature_envelope_tuple.items[2]
        .canonical_bytes()
        .to_vec();
    let changed_signature_position = changed_signature.len() / 2;
    changed_signature[changed_signature_position] ^= 0x80;
    changed_signature_envelope_tuple.items[2] =
        CanonicalItem::fixed_bytes(changed_signature).unwrap();
    assert_eq!(
        verify_masked_ballot_bivariate_commitment_root_signature_320(
            fixture.layout,
            &root_body_bytes,
            &fixture.roster,
            &changed_signature_envelope_tuple.encode().unwrap(),
        ),
        Err(MaskedBallotBivariateCommitmentError320::InvalidSignature)
    );

    let private_row_body_bytes = fixture
        .inventory
        .private_row_body(0)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut changed_private_row_tuple = decode_tuple(&private_row_body_bytes);
    let mut changed_payload = changed_private_row_tuple.items[7]
        .canonical_bytes()
        .to_vec();
    changed_payload[0] ^= 1;
    changed_private_row_tuple.items[7] = CanonicalItem::fixed_bytes(changed_payload).unwrap();
    assert!(matches!(
        verify_masked_ballot_bivariate_private_row_320(
            &authenticated_root,
            &changed_private_row_tuple.encode().unwrap(),
        ),
        Err(MaskedBallotBivariateCommitmentError320::CommitmentMismatch { leaf_ordinal: 0 })
    ));

    let mut short_private_row_tuple = decode_tuple(&private_row_body_bytes);
    let mut short_payload = short_private_row_tuple.items[7].canonical_bytes().to_vec();
    short_payload.pop();
    short_private_row_tuple.items[7] = CanonicalItem::fixed_bytes(short_payload).unwrap();
    assert!(matches!(
        verify_masked_ballot_bivariate_private_row_320(
            &authenticated_root,
            &short_private_row_tuple.encode().unwrap(),
        ),
        Err(
            MaskedBallotBivariateCommitmentError320::PrivateRowPayloadByteLength {
                expected: 1_040,
                actual: 1_039,
            }
        )
    ));

    for bytes in [
        &root_body_bytes,
        &valid_signature_envelope_bytes,
        &private_row_body_bytes,
    ] {
        assert!(bytes.len() > 1);
        let truncated = &bytes[..bytes.len() - 1];
        if bytes.len() == root_body_bytes.len() {
            assert!(
                verify_masked_ballot_bivariate_commitment_root_signature_320(
                    fixture.layout,
                    truncated,
                    &fixture.roster,
                    &valid_signature_envelope_bytes,
                )
                .is_err()
            );
        } else if bytes.len() == valid_signature_envelope_bytes.len() {
            assert!(
                verify_masked_ballot_bivariate_commitment_root_signature_320(
                    fixture.layout,
                    &root_body_bytes,
                    &fixture.roster,
                    truncated,
                )
                .is_err()
            );
        } else {
            assert!(
                verify_masked_ballot_bivariate_private_row_320(&authenticated_root, truncated)
                    .is_err()
            );
        }
    }
}

#[test]
fn an_author_signed_but_locally_invalid_row_is_refused() {
    let fixture = completion_fixture(0x23, 0x33);
    let holder_roster_position = 0;
    let original_private_row_body_bytes = fixture
        .inventory
        .private_row_body(holder_roster_position)
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut changed_private_row_tuple = decode_tuple(&original_private_row_body_bytes);
    let mut changed_payload = changed_private_row_tuple.items[7]
        .canonical_bytes()
        .to_vec();
    let changed_opening_position = 1_usize;
    let opening_byte_length = BinaryFieldElement320::CANONICAL_BYTE_LENGTH
        + MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH;
    let changed_opening_offset = changed_opening_position * opening_byte_length;
    changed_payload[changed_opening_offset] ^= 1;

    let changed_value = BinaryFieldElement320::from_canonical_bytes(
        &changed_payload[changed_opening_offset
            ..changed_opening_offset + BinaryFieldElement320::CANONICAL_BYTE_LENGTH],
    )
    .unwrap();
    let changed_salt = changed_payload[changed_opening_offset
        + BinaryFieldElement320::CANONICAL_BYTE_LENGTH
        ..changed_opening_offset + opening_byte_length]
        .try_into()
        .unwrap();
    let changed_coordinate = fixture
        .layout
        .holder_coordinates(holder_roster_position)
        .unwrap()[changed_opening_position];
    let changed_leaf_ordinal = fixture.layout.leaf_ordinal(changed_coordinate).unwrap();
    let mut changed_commitment_digests =
        fixture.inventory.root_body().commitment_digests().to_vec();
    changed_commitment_digests[usize::try_from(changed_leaf_ordinal).unwrap()] =
        derive_masked_ballot_bivariate_commitment_digest_320(
            fixture.layout,
            changed_coordinate,
            changed_value,
            changed_salt,
        )
        .unwrap();
    let changed_root_body =
        MaskedBallotBivariateCommitmentRootBody320::new(fixture.layout, changed_commitment_digests)
            .unwrap();
    changed_private_row_tuple.items[2] =
        CanonicalItem::hash512(changed_root_body.identity().unwrap().into_bytes());
    changed_private_row_tuple.items[7] = CanonicalItem::fixed_bytes(changed_payload).unwrap();

    let changed_root_body_bytes = changed_root_body.canonical_bytes().unwrap();
    let changed_signature_envelope_bytes = sign_root(
        &changed_root_body,
        &fixture.signing_keys[usize::from(fixture.layout.author_roster_position())],
        0x43,
    );
    let changed_authenticated_root = verify_masked_ballot_bivariate_commitment_root_signature_320(
        fixture.layout,
        &changed_root_body_bytes,
        &fixture.roster,
        &changed_signature_envelope_bytes,
    )
    .unwrap();
    assert_eq!(
        verify_masked_ballot_bivariate_private_row_320(
            &changed_authenticated_root,
            &changed_private_row_tuple.encode().unwrap(),
        ),
        Err(
            MaskedBallotBivariateCommitmentError320::LocalRowDegreeMismatch {
                holder_roster_position,
            }
        )
    );
}

#[test]
fn every_admitted_roster_derives_a_bijective_flat_inventory_and_fixed_holder_rows() {
    for participant_count in 3..=20_u16 {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(participant_count, 2, 1).unwrap(),
        )
        .unwrap();
        let preparation_context = TallyPreparationContext::new(
            deterministic_hash(0x54, u64::from(participant_count)),
            deterministic_hash(0x64, u64::from(participant_count)),
            [u8::try_from(participant_count).unwrap(); 32],
            &circuit,
        )
        .unwrap();
        let layout = MaskedBallotBivariateCommitmentLayout320::derive(
            deterministic_hash(0x74, u64::from(participant_count)),
            preparation_context,
            deterministic_hash(0x84, u64::from(participant_count)),
            participant_count - 1,
        )
        .unwrap();
        let expected_crosspoint_leaf_count =
            u64::from(participant_count) * u64::from(participant_count - 1) / 2;
        assert_eq!(
            layout.reconstruction_threshold(),
            roster_parameters.reconstruction_threshold
        );
        assert_eq!(
            layout.secret_axis_leaf_count(),
            u64::from(participant_count)
        );
        assert_eq!(
            layout.crosspoint_leaf_count(),
            expected_crosspoint_leaf_count
        );
        assert_eq!(
            layout.leaf_count(),
            u64::from(participant_count) + expected_crosspoint_leaf_count
        );
        let coordinates = layout.coordinates();
        assert_eq!(
            coordinates.len(),
            usize::try_from(layout.leaf_count()).unwrap()
        );
        assert_eq!(
            coordinates.iter().copied().collect::<BTreeSet<_>>().len(),
            coordinates.len()
        );
        for (leaf_ordinal, coordinate) in coordinates.iter().copied().enumerate() {
            assert_eq!(
                layout.leaf_ordinal(coordinate).unwrap(),
                u64::try_from(leaf_ordinal).unwrap()
            );
        }

        let bundle = patterned_bundle(&circuit, u8::try_from(participant_count).unwrap());
        let polynomial = polynomial_for_bundle(
            layout,
            &bundle,
            u8::try_from(participant_count).unwrap().wrapping_add(0x41),
        );
        let inventory = MaskedBallotBivariateCommitmentInventory320::create(
            layout,
            &polynomial,
            deterministic_salts(
                layout.leaf_count(),
                u8::try_from(participant_count).unwrap().wrapping_add(0x61),
            ),
        )
        .unwrap();
        assert_eq!(
            inventory.root_body().commitment_digests().len(),
            coordinates.len()
        );
        for holder_roster_position in 0..participant_count {
            assert_eq!(
                layout
                    .holder_coordinates(holder_roster_position)
                    .unwrap()
                    .len(),
                usize::from(participant_count)
            );
            assert_eq!(
                inventory
                    .private_row_body(holder_roster_position)
                    .unwrap()
                    .holder_roster_position(),
                holder_roster_position
            );
        }
    }
}

#[test]
fn commitment_digest_binds_layout_coordinate_value_and_salt() {
    let fixture = completion_fixture(0x35, 0x45);
    let coordinate = MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
        lower_holder_roster_position: 2,
        upper_holder_roster_position: 7,
    };
    let value = BinaryFieldElement320::from_low_polynomial_u16(0x1234);
    let salt = [0x55; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH];
    let baseline = derive_masked_ballot_bivariate_commitment_digest_320(
        fixture.layout,
        coordinate,
        value,
        salt,
    )
    .unwrap();

    let mut changed_salt = salt;
    changed_salt[63] ^= 1;
    let changed_value = value.add(BinaryFieldElement320::ONE);
    let changed_coordinate = MaskedBallotBivariateCommitmentCoordinate320::Crosspoint {
        lower_holder_roster_position: 2,
        upper_holder_roster_position: 8,
    };
    let changed_layout = MaskedBallotBivariateCommitmentLayout320::derive(
        fixture.layout.parameter_identity(),
        fixture.layout.preparation_context(),
        changed_hash(fixture.layout.preparation_record_identity()),
        fixture.layout.author_roster_position(),
    )
    .unwrap();
    let candidates = [
        derive_masked_ballot_bivariate_commitment_digest_320(
            fixture.layout,
            coordinate,
            changed_value,
            salt,
        )
        .unwrap(),
        derive_masked_ballot_bivariate_commitment_digest_320(
            fixture.layout,
            coordinate,
            value,
            changed_salt,
        )
        .unwrap(),
        derive_masked_ballot_bivariate_commitment_digest_320(
            fixture.layout,
            changed_coordinate,
            value,
            salt,
        )
        .unwrap(),
        derive_masked_ballot_bivariate_commitment_digest_320(
            changed_layout,
            coordinate,
            value,
            salt,
        )
        .unwrap(),
    ];
    assert!(candidates.iter().all(|candidate| *candidate != baseline));
    assert_eq!(
        candidates.iter().copied().collect::<HashSet<_>>().len(),
        candidates.len()
    );
}

#[test]
fn secret_debug_output_redacts_openings_rows_and_signatures() {
    let fixture = completion_fixture(0x56, 0x66);
    let private_row = fixture.inventory.private_row_body(0).unwrap();
    let signature_envelope = MaskedBallotBivariateCommitmentSignatureEnvelope320::new(
        fixture.inventory.root_body().identity().unwrap(),
        [0x76; ml_dsa_65::SIG_LEN],
    );
    let output = format!(
        "{:?} {:?} {:?}",
        fixture.inventory, private_row, signature_envelope
    );
    assert!(output.contains("[redacted]"));
    assert!(!output.contains("MaskedBallotBivariateCommitmentOpening320 { coordinate"));
    assert!(!output.contains(&"76".repeat(32)));
}

struct CompletionFixture {
    roster: Roster,
    signing_keys: Vec<ml_dsa_65::PrivateKey>,
    circuit: CompiledTallyCircuit,
    layout: MaskedBallotBivariateCommitmentLayout320,
    bundle: MaskedBallotBundle320,
    polynomial: MaskedBallotSymmetricBivariatePolynomial320,
    inventory: MaskedBallotBivariateCommitmentInventory320,
}

fn completion_fixture(roster_marker: u8, bundle_marker: u8) -> CompletionFixture {
    let (roster, signing_keys) =
        roster_and_signing_keys(FOUNDATION_PROFILE.participant_count, roster_marker);
    let circuit = completion_circuit();
    let context = completion_context(&roster, &circuit, roster_marker.wrapping_add(1));
    let layout = MaskedBallotBivariateCommitmentLayout320::derive(
        deterministic_hash(roster_marker.wrapping_add(2), 0),
        context,
        deterministic_hash(roster_marker.wrapping_add(3), 0),
        4,
    )
    .unwrap();
    let bundle = patterned_bundle(&circuit, bundle_marker);
    let polynomial = polynomial_for_bundle(layout, &bundle, bundle_marker.wrapping_add(1));
    let inventory = MaskedBallotBivariateCommitmentInventory320::create(
        layout,
        &polynomial,
        deterministic_salts(layout.leaf_count(), bundle_marker.wrapping_add(2)),
    )
    .unwrap();
    CompletionFixture {
        roster,
        signing_keys,
        circuit,
        layout,
        bundle,
        polynomial,
        inventory,
    }
}

fn authenticate_root(
    layout: MaskedBallotBivariateCommitmentLayout320,
    inventory: &MaskedBallotBivariateCommitmentInventory320,
    roster: &Roster,
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> AuthorAuthenticatedMaskedBallotBivariateCommitmentRoot320 {
    let root_body_bytes = inventory.root_body().canonical_bytes().unwrap();
    let signature_envelope_bytes = sign_root(inventory.root_body(), signing_key, signature_marker);
    verify_masked_ballot_bivariate_commitment_root_signature_320(
        layout,
        &root_body_bytes,
        roster,
        &signature_envelope_bytes,
    )
    .unwrap()
}

fn sign_root(
    root_body: &MaskedBallotBivariateCommitmentRootBody320,
    signing_key: &ml_dsa_65::PrivateKey,
    signature_marker: u8,
) -> Vec<u8> {
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let signature = signing_key
        .try_sign_with_seed(
            &[signature_marker; 32],
            &root_body_bytes,
            MASKED_BALLOT_BIVARIATE_COMMITMENT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    MaskedBallotBivariateCommitmentSignatureEnvelope320::new(
        root_body.identity().unwrap(),
        signature,
    )
    .canonical_bytes()
    .unwrap()
}

fn polynomial_for_bundle(
    layout: MaskedBallotBivariateCommitmentLayout320,
    bundle: &MaskedBallotBundle320,
    marker: u8,
) -> MaskedBallotSymmetricBivariatePolynomial320 {
    let reconstruction_threshold = usize::from(layout.reconstruction_threshold());
    let random_coefficient_count =
        reconstruction_threshold * (reconstruction_threshold + 1) / 2 - 1;
    let random_coefficients = (0..random_coefficient_count)
        .map(|coefficient_position| {
            BinaryFieldElement320::from_low_polynomial_u16(
                u16::from(marker)
                    .wrapping_mul(257)
                    .wrapping_add(u16::try_from(coefficient_position + 1).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    MaskedBallotSymmetricBivariatePolynomial320::from_bundle_and_random_coefficients(
        layout.participant_count(),
        bundle,
        &random_coefficients,
    )
    .unwrap()
}

fn patterned_bundle(circuit: &CompiledTallyCircuit, marker: u8) -> MaskedBallotBundle320 {
    let mut bytes = vec![0_u8; canonical_bundle_byte_length(circuit)];
    for (byte_position, byte) in bytes.iter_mut().enumerate() {
        *byte = marker.wrapping_add(u8::try_from(byte_position).unwrap().wrapping_mul(29));
    }
    let input_bit_count = masked_ballot_bundle_input_bit_count(circuit).unwrap();
    let used_bit_count_in_last_byte = input_bit_count % 8;
    if used_bit_count_in_last_byte != 0 {
        let used_bit_mask = (1_u8 << used_bit_count_in_last_byte) - 1;
        *bytes.last_mut().unwrap() &= used_bit_mask;
    }
    MaskedBallotBundle320::from_canonical_bytes(circuit, &bytes).unwrap()
}

fn canonical_bundle_byte_length(circuit: &CompiledTallyCircuit) -> usize {
    masked_ballot_bundle_input_bit_count(circuit)
        .unwrap()
        .div_ceil(8)
}

fn deterministic_salts(
    leaf_count: u64,
    marker: u8,
) -> Vec<[u8; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH]> {
    (0..leaf_count)
        .map(|leaf_ordinal| {
            let mut salt = [marker; MASKED_BALLOT_BIVARIATE_COMMITMENT_SALT_BYTE_LENGTH];
            salt[..8].copy_from_slice(&leaf_ordinal.to_le_bytes());
            salt[63] ^= u8::try_from(leaf_ordinal % 251).unwrap();
            salt
        })
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
            signing_seed[0] = marker.wrapping_add(u8::try_from(roster_position).unwrap());
            let (signing_verification_key, signing_key) =
                ml_dsa_65::KG::keygen_from_seed(&signing_seed);
            signing_keys.push(signing_key);

            let mut mailbox_seed = [marker.wrapping_add(0x31); 32];
            mailbox_seed[0] ^= u8::try_from(roster_position).unwrap();
            let mut mailbox_fallback_seed = [marker.wrapping_add(0x53); 32];
            mailbox_fallback_seed[31] ^= u8::try_from(roster_position).unwrap();
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

fn completion_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}

fn completion_context(
    roster: &Roster,
    circuit: &CompiledTallyCircuit,
    attempt_marker: u8,
) -> TallyPreparationContext {
    TallyPreparationContext::new(
        deterministic_hash(0xd1, 0),
        roster.roster_hash().unwrap(),
        [attempt_marker; 32],
        circuit,
    )
    .unwrap()
}

fn deterministic_hash(marker: u8, ordinal: u64) -> Hash512 {
    let mut bytes = [marker; Hash512::BYTE_LENGTH];
    bytes[..8].copy_from_slice(&ordinal.to_le_bytes());
    Hash512::from_bytes(bytes)
}

fn changed_hash(hash: Hash512) -> Hash512 {
    let mut bytes = hash.into_bytes();
    bytes[0] ^= 0x80;
    Hash512::from_bytes(bytes)
}

fn decode_tuple(bytes: &[u8]) -> CanonicalTuple {
    CanonicalTuple::decode(bytes, &CanonicalDecodeLimits::default()).unwrap()
}
