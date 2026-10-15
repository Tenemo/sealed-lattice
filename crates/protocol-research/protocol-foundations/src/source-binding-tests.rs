use super::*;
use crate::{
    BodyDigest, Credential, SIGNATURE_BYTES,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalTuple, RegistrationHeader,
        StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, verify_poll},
    registration::{RegistrationVerifier, session::RegistrationSession},
    verify_registration_signature,
};

fn poll(maximum: usize, options: usize) -> VerifiedPoll {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..options)
        .map(|index| {
            OptionDefinition::new(
                index as u16,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(
        Manifest::new(text("Question"), options).unwrap(),
        1,
        maximum as u16,
    )
    .unwrap();
    let packet = Credential::from_seed([1; 64])
        .create_poll(draft, [2; 64], [3; 32])
        .unwrap();
    verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap()
}

fn header(poll: &VerifiedPoll, credential: &Credential) -> RegistrationHeader {
    RegistrationHeader {
        username: normalize_username(b"Participant").unwrap(),
        poll: poll.identity(),
        signing_public: *credential.signing_public(),
        recipient_key_hash: [5; 64],

        source_bindings: vec![[6; 64]; fhe_key_families(poll).len()],
    }
}

#[test]
fn family_order_covers_every_allowed_profile_without_a_roster_alias() {
    for (maximum, options) in [(3, 2), (10, 10), (20, 20)] {
        let poll = poll(maximum, options);
        let actual = fhe_key_families(&poll);
        let mut independent = Vec::new();
        for count in 3..=maximum {
            let profile = Profile::new(count, options).unwrap();
            let key = (
                profile.ciphertext_modulus().to_bytes(),
                profile.fhe_common_sample_bits(),
            );
            if !independent.contains(&key) {
                independent.push(key.clone());
            }
            let index = independent.iter().position(|value| value == &key).unwrap();
            assert_eq!(fhe_key_family_index(&poll, profile).unwrap(), index);
            assert_eq!(
                (
                    actual[index].ciphertext_modulus().to_bytes(),
                    actual[index].fhe_common_sample_bits()
                ),
                key
            );
        }
        assert_eq!(actual.len(), independent.len());
        assert!(actual.len() <= maximum_fhe_key_family_count());
        assert!(
            fhe_key_family_index(
                &poll,
                Profile::new(3, if options == 2 { 3 } else { 2 }).unwrap()
            )
            .is_err()
        );
        if maximum < 20 {
            assert!(
                fhe_key_family_index(&poll, Profile::new(maximum + 1, options).unwrap()).is_err()
            );
        }
    }
}

#[test]
fn public_and_helper_registration_ingress_require_the_verified_poll_inventory() {
    let poll = poll(10, 10);
    let credential = Credential::from_seed([7; 64]);
    let mut header = header(&poll, &credential);
    let encoded = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &encoded, &[0; SIGNATURE_BYTES]).is_ok());
    assert!(RegistrationSession::open(&poll, 0, &encoded, &[0; SIGNATURE_BYTES]).is_ok());
    header.source_bindings.pop();
    let missing = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &missing, &[0; SIGNATURE_BYTES]).is_err());
    assert!(RegistrationSession::open(&poll, 0, &missing, &[0; SIGNATURE_BYTES]).is_err());
    header.source_bindings.extend([[8; 64], [9; 64]]);
    let extra = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &extra, &[0; SIGNATURE_BYTES]).is_err());
    assert!(RegistrationSession::open(&poll, 0, &extra, &[0; SIGNATURE_BYTES]).is_err());
}

#[test]
fn registration_signature_binds_ordered_encrypted_sources() {
    let poll = poll(10, 10);
    let mut credential = Credential::from_seed([7; 64]);
    let mut header = header(&poll, &credential);
    for (index, digest) in header.source_bindings.iter_mut().enumerate() {
        digest[0] = index as u8;
    }
    let digest = |header: &RegistrationHeader| {
        BodyDigest::from_header(&header.encode().unwrap(), poll.identity()).unwrap()
    };
    let signature = credential.sign_registration(digest(&header)).unwrap();
    assert!(verify_registration_signature(digest(&header), &signature));
    header.source_bindings.swap(0, 1);
    assert!(!verify_registration_signature(digest(&header), &signature));
    header.source_bindings.swap(0, 1);
    header.source_bindings[0][63] ^= 1;
    assert!(!verify_registration_signature(digest(&header), &signature));
    let bytes = header.encode().unwrap();
    let mut changed = CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
    changed.items[5] = CanonicalItem::variable_bytes([0; 64]).unwrap();
    assert!(RegistrationHeader::decode_prefix(&changed.encode().unwrap()).is_err());
}
