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
    pseudorandom_zero_sharing_seed_catalog_320::{
        PseudorandomZeroSharingSeedCatalogLayout320, PseudorandomZeroSharingSeedCatalogTree320,
    },
    pseudorandom_zero_sharing_seed_catalog_signature_320::{
        ML_DSA_65_SIGNATURE_BYTE_LENGTH,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN,
        PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
        PseudorandomZeroSharingSeedCatalogSignatureError,
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320,
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320,
    },
};

#[test]
fn every_completion_contributor_signature_matches_only_its_roster_key_and_root() {
    assert_eq!(ML_DSA_65_SIGNATURE_BYTE_LENGTH, ml_dsa_65::SIG_LEN);
    let (roster, signing_keys) = roster_and_signing_keys(0x21);
    let context = completion_context(&roster, 0x31);

    for contributor_position in 0..FOUNDATION_PROFILE.participant_count {
        let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
            Hash512::from_bytes([0x41; 64]),
            context,
            contributor_position,
        )
        .unwrap();
        let tree = PseudorandomZeroSharingSeedCatalogTree320::create(
            layout,
            deterministic_commitment_digests(layout.leaf_count(), contributor_position as u8),
        )
        .unwrap();
        let root_body = tree.root_body();
        let root_body_bytes = root_body.canonical_bytes().unwrap();
        let state_reservation_identity = deterministic_hash(0x51, u64::from(contributor_position));
        let signature_body = PseudorandomZeroSharingSeedCatalogRootSignatureBody320::new(
            root_body,
            state_reservation_identity,
        )
        .unwrap();
        assert_eq!(signature_body.contributor_position(), contributor_position);
        assert_eq!(
            signature_body.root_body_identity(),
            root_body.identity().unwrap()
        );
        assert_eq!(
            signature_body.state_reservation_identity(),
            state_reservation_identity
        );
        let signature_body_bytes = signature_body.canonical_bytes().unwrap();
        let signature = signing_keys[usize::from(contributor_position)]
            .try_sign_with_seed(
                &[0x61_u8.wrapping_add(contributor_position as u8); 32],
                &signature_body_bytes,
                PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
            )
            .unwrap();
        let envelope =
            PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(signature_body, signature);
        assert_eq!(envelope.signature_body(), signature_body);
        let envelope_bytes = envelope.canonical_bytes().unwrap();

        let expected_signature_body_byte_length = 8
            + 7 * 6
            + 4
            + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN.len()
            + 3 * Hash512::BYTE_LENGTH
            + 3 * 2;
        assert_eq!(
            signature_body_bytes.len(),
            expected_signature_body_byte_length
        );
        let expected_envelope_byte_length = 8
            + 3 * 6
            + 4
            + PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN.len()
            + 4
            + expected_signature_body_byte_length
            + ML_DSA_65_SIGNATURE_BYTE_LENGTH;
        assert_eq!(envelope_bytes.len(), expected_envelope_byte_length);

        let matched = verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &envelope_bytes,
        )
        .unwrap();
        assert_eq!(matched.root_body(), root_body);
        assert_eq!(matched.root_body_identity(), root_body.identity().unwrap());
        assert_eq!(
            matched.state_reservation_identity(),
            state_reservation_identity
        );
    }
}

#[test]
fn verifier_refuses_wrong_signer_signature_context_state_root_and_roster() {
    let (roster, signing_keys) = roster_and_signing_keys(0x71);
    let context = completion_context(&roster, 0x73);
    let contributor_position = 4;
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0x75; 64]),
        context,
        contributor_position,
    )
    .unwrap();
    let tree = PseudorandomZeroSharingSeedCatalogTree320::create(
        layout,
        deterministic_commitment_digests(layout.leaf_count(), 0x77),
    )
    .unwrap();
    let root_body = tree.root_body();
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let state_reservation_identity = Hash512::from_bytes([0x79; 64]);
    let signature_body = PseudorandomZeroSharingSeedCatalogRootSignatureBody320::new(
        root_body,
        state_reservation_identity,
    )
    .unwrap();
    let signature_body_bytes = signature_body.canonical_bytes().unwrap();

    let wrong_signer_signature = signing_keys[0]
        .try_sign_with_seed(
            &[0x7b; 32],
            &signature_body_bytes,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    assert_eq!(
        verify_with_envelope(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            signature_body,
            wrong_signer_signature,
        ),
        Err(PseudorandomZeroSharingSeedCatalogSignatureError::InvalidSignature)
    );

    let wrong_context_signature = signing_keys[usize::from(contributor_position)]
        .try_sign_with_seed(
            &[0x7d; 32],
            &signature_body_bytes,
            b"sealed-lattice/v1/preparation/wrong-purpose",
        )
        .unwrap();
    assert_eq!(
        verify_with_envelope(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            signature_body,
            wrong_context_signature,
        ),
        Err(PseudorandomZeroSharingSeedCatalogSignatureError::InvalidSignature)
    );

    let valid_signature = signing_keys[usize::from(contributor_position)]
        .try_sign_with_seed(
            &[0x7f; 32],
            &signature_body_bytes,
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    let valid_envelope_bytes = PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(
        signature_body,
        valid_signature,
    )
    .canonical_bytes()
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            changed_hash(state_reservation_identity),
            &roster,
            &valid_envelope_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch {
                field: "state-reservation identity"
            }
        )
    ));

    let mut changed_root_body_tuple = decode_tuple(&root_body_bytes);
    changed_root_body_tuple.items[14] = CanonicalItem::hash512([0x81; 64]);
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &changed_root_body_tuple.encode().unwrap(),
            state_reservation_identity,
            &roster,
            &valid_envelope_bytes,
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch {
                field: "root-body identity"
            }
        )
    ));

    let (other_roster, _) = roster_and_signing_keys(0x83);
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &other_roster,
            &valid_envelope_bytes,
        ),
        Err(PseudorandomZeroSharingSeedCatalogSignatureError::RosterMismatch)
    );

    let mut changed_signature_envelope = valid_envelope_bytes.clone();
    *changed_signature_envelope.last_mut().unwrap() ^= 0x80;
    assert_eq!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &changed_signature_envelope,
        ),
        Err(PseudorandomZeroSharingSeedCatalogSignatureError::InvalidSignature)
    );
}

#[test]
fn authorization_body_binds_every_field_and_envelope_decoder_is_strict() {
    let (roster, signing_keys) = roster_and_signing_keys(0x91);
    let context = completion_context(&roster, 0x93);
    let layout = PseudorandomZeroSharingSeedCatalogLayout320::derive(
        Hash512::from_bytes([0x95; 64]),
        context,
        1,
    )
    .unwrap();
    let tree = PseudorandomZeroSharingSeedCatalogTree320::create(
        layout,
        deterministic_commitment_digests(layout.leaf_count(), 0x97),
    )
    .unwrap();
    let root_body = tree.root_body();
    let root_body_bytes = root_body.canonical_bytes().unwrap();
    let state_reservation_identity = Hash512::from_bytes([0x99; 64]);
    let signature_body = PseudorandomZeroSharingSeedCatalogRootSignatureBody320::new(
        root_body,
        state_reservation_identity,
    )
    .unwrap();
    let signature = signing_keys[1]
        .try_sign_with_seed(
            &[0x9b; 32],
            &signature_body.canonical_bytes().unwrap(),
            PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_CONTEXT,
        )
        .unwrap();
    let envelope_bytes =
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(signature_body, signature)
            .canonical_bytes()
            .unwrap();

    let envelope_tuple = decode_tuple(&envelope_bytes);
    let signature_body_bytes = envelope_tuple.items[1]
        .variable_value_bytes()
        .unwrap()
        .to_vec();
    let signature_body_tuple = decode_tuple(&signature_body_bytes);
    for field_position in 1..signature_body_tuple.items.len() {
        let mut changed_body_tuple = signature_body_tuple.clone();
        changed_body_tuple.items[field_position] = match field_position {
            1 | 5 | 6 => CanonicalItem::hash512([field_position as u8; 64]),
            2..=4 => CanonicalItem::unsigned16(0xffff),
            _ => unreachable!(),
        };
        let mut changed_envelope_tuple = envelope_tuple.clone();
        changed_envelope_tuple.items[1] =
            CanonicalItem::variable_bytes(changed_body_tuple.encode().unwrap()).unwrap();
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
                layout,
                &root_body_bytes,
                state_reservation_identity,
                &roster,
                &changed_envelope_tuple.encode().unwrap(),
            )
            .is_err(),
            "signature body field {field_position} must bind"
        );
    }

    let mut wrong_body_domain = signature_body_tuple.clone();
    wrong_body_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_ENVELOPE_DOMAIN,
    )
    .unwrap();
    let mut wrong_body_domain_envelope = envelope_tuple.clone();
    wrong_body_domain_envelope.items[1] =
        CanonicalItem::variable_bytes(wrong_body_domain.encode().unwrap()).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &wrong_body_domain_envelope.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut wrong_envelope_domain = envelope_tuple.clone();
    wrong_envelope_domain.items[0] = CanonicalItem::nonempty_ascii(
        PSEUDORANDOM_ZERO_SHARING_SEED_CATALOG_ROOT_SIGNATURE_BODY_DOMAIN,
    )
    .unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &wrong_envelope_domain.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch {
                field: "object domain"
            }
        )
    ));

    let mut short_signature_envelope = envelope_tuple.clone();
    short_signature_envelope.items[2] =
        CanonicalItem::fixed_bytes([0_u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH - 1]).unwrap();
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &short_signature_envelope.encode().unwrap(),
        ),
        Err(PseudorandomZeroSharingSeedCatalogSignatureError::SignatureByteLength {
            expected: ML_DSA_65_SIGNATURE_BYTE_LENGTH,
            actual,
        }) if actual == ML_DSA_65_SIGNATURE_BYTE_LENGTH - 1
    ));

    let mut extra_item_envelope = envelope_tuple.clone();
    extra_item_envelope.items.push(CanonicalItem::unsigned16(1));
    assert!(matches!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &extra_item_envelope.encode().unwrap(),
        ),
        Err(
            PseudorandomZeroSharingSeedCatalogSignatureError::ObjectMismatch {
                field: "item count"
            }
        )
    ));

    for truncated_length in 0..envelope_bytes.len() {
        assert!(
            verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
                layout,
                &root_body_bytes,
                state_reservation_identity,
                &roster,
                &envelope_bytes[..truncated_length],
            )
            .is_err()
        );
    }
    assert!(
        verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
            layout,
            &root_body_bytes,
            state_reservation_identity,
            &roster,
            &[0_u8; 8_193],
        )
        .is_err()
    );
    assert!(
        format!(
            "{:?}",
            PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(
                signature_body,
                [0xa1; ML_DSA_65_SIGNATURE_BYTE_LENGTH]
            )
        )
        .contains("[redacted]")
    );
}

fn verify_with_envelope(
    layout: PseudorandomZeroSharingSeedCatalogLayout320,
    root_body_bytes: &[u8],
    state_reservation_identity: Hash512,
    roster: &Roster,
    signature_body: PseudorandomZeroSharingSeedCatalogRootSignatureBody320,
    signature: [u8; ML_DSA_65_SIGNATURE_BYTE_LENGTH],
) -> Result<
    super::pseudorandom_zero_sharing_seed_catalog_signature_320::RosterSignatureMatchedPseudorandomZeroSharingSeedCatalogRoot320,
    PseudorandomZeroSharingSeedCatalogSignatureError,
>{
    let envelope_bytes =
        PseudorandomZeroSharingSignedSeedCatalogRootEnvelope320::new(signature_body, signature)
            .canonical_bytes()
            .unwrap();
    verify_pseudorandom_zero_sharing_seed_catalog_root_signature_320(
        layout,
        root_body_bytes,
        state_reservation_identity,
        roster,
        &envelope_bytes,
    )
}

fn roster_and_signing_keys(marker: u8) -> (Roster, Vec<ml_dsa_65::PrivateKey>) {
    let mut signing_keys = Vec::with_capacity(usize::from(FOUNDATION_PROFILE.participant_count));
    let entries = (0..FOUNDATION_PROFILE.participant_count)
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

fn completion_context(roster: &Roster, attempt_marker: u8) -> TallyPreparationContext {
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
        Hash512::from_bytes([0xd1; 64]),
        roster.roster_hash().unwrap(),
        [attempt_marker; 32],
        &circuit,
    )
    .unwrap()
}

fn deterministic_commitment_digests(leaf_count: u64, marker: u8) -> Vec<Hash512> {
    (0..leaf_count)
        .map(|leaf_ordinal| deterministic_hash(marker, leaf_ordinal))
        .collect()
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
