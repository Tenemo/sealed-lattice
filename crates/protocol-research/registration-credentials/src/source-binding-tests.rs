use super::*;
use crate::{
    BodyDigest, SIGNATURE_BYTES,
    foundation::{
        CanonicalDecodeLimits, CanonicalTuple, RegistrationHeader, StabilizedDisplayText,
        manifest::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, verify_poll},
    registration::{RegistrationVerifier, session::RegistrationSession},
    verify_registration_signature,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
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
    let packet = Credential::from_seed([1; 32])
        .create_poll(draft, [2; 64], [3; 32])
        .unwrap();
    verify_poll(packet.identity, [2; 64], &packet.body, &packet.signature).unwrap()
}

fn header(poll: &VerifiedPoll, credential: &Credential) -> RegistrationHeader {
    RegistrationHeader {
        username: normalize_username(b"Participant").unwrap(),
        poll: poll.identity(),
        runtime: poll.runtime(),
        signing_public: *credential.signing_public(),
        recipient_key_hash: [5; 64],

        fhe_key_commitments: vec![[6; 64]; fhe_key_families(poll).len()],
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
    let credential = Credential::from_seed([7; 32]);
    let mut header = header(&poll, &credential);
    let encoded = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &encoded, &[0; SIGNATURE_BYTES]).is_ok());
    assert!(RegistrationSession::open(&poll, 0, &encoded, &[0; SIGNATURE_BYTES]).is_ok());
    header.fhe_key_commitments.pop();
    let missing = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &missing, &[0; SIGNATURE_BYTES]).is_err());
    assert!(RegistrationSession::open(&poll, 0, &missing, &[0; SIGNATURE_BYTES]).is_err());
    header.fhe_key_commitments.extend([[8; 64], [9; 64]]);
    let extra = header.encode().unwrap();
    assert!(RegistrationVerifier::new(&poll, &extra, &[0; SIGNATURE_BYTES]).is_err());
    assert!(RegistrationSession::open(&poll, 0, &extra, &[0; SIGNATURE_BYTES]).is_err());
}

#[test]
fn registration_signature_binds_ordered_coordinate_commitments() {
    let poll = poll(10, 10);
    let mut credential = Credential::from_seed([7; 32]);
    let mut header = header(&poll, &credential);
    for (index, digest) in header.fhe_key_commitments.iter_mut().enumerate() {
        digest[0] = index as u8;
    }
    let digest = |header: &RegistrationHeader| {
        BodyDigest::from_header(&header.encode().unwrap(), poll.identity(), poll.runtime()).unwrap()
    };
    let signature = credential.sign_registration(digest(&header)).unwrap();
    assert!(verify_registration_signature(digest(&header), &signature));
    header.fhe_key_commitments.swap(0, 1);
    assert!(!verify_registration_signature(digest(&header), &signature));
    header.fhe_key_commitments.swap(0, 1);
    header.fhe_key_commitments[0][63] ^= 1;
    assert!(!verify_registration_signature(digest(&header), &signature));
    let bytes = header.encode().unwrap();
    let mut changed = CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
    changed.items[6] = CanonicalItem::variable_bytes([0; 64]).unwrap();
    assert!(RegistrationHeader::decode_prefix(&changed.encode().unwrap()).is_err());
}

fn zero_coordinate(mut hash: FheKeyCommitmentHasher, chunk: usize) -> [u8; 64] {
    let length = hash.length;
    let bytes = vec![0; chunk];
    for offset in (hash.received..length).step_by(chunk) {
        hash.push(offset, &bytes[..chunk.min(length - offset)])
            .unwrap();
    }
    hash.finish().unwrap()
}

#[test]
fn coordinate_commitment_matches_independent_framing_and_transport_partitions() {
    let poll = poll(3, 2);
    let credential = Credential::from_seed([7; 32]);
    let profile = Profile::new(3, 2).unwrap();
    let salt = [8; 64];
    let modulus = profile.ciphertext_modulus().to_bytes();
    let length = DEGREE * (1 + modulus.len());
    let mut prefix = CanonicalTuple::new(
        1,
        1,
        vec![
            CanonicalItem::nonempty_ascii("sealed-lattice/registered-fhe-key/v1").unwrap(),
            CanonicalItem::fixed_bytes(credential.signing_public()).unwrap(),
            CanonicalItem::fixed_bytes(salt).unwrap(),
            CanonicalItem::hash512(poll.identity()),
            CanonicalItem::hash512(poll.runtime()),
            CanonicalItem::variable_bytes(&modulus).unwrap(),
            CanonicalItem::unsigned64(profile.fhe_common_sample_bits() as u64),
            CanonicalItem::variable_bytes([]).unwrap(),
        ],
    )
    .encode()
    .unwrap();
    let end = prefix.len();
    prefix[end - 8..end - 4].copy_from_slice(&((length + 4) as u32).to_le_bytes());
    prefix[end - 4..].copy_from_slice(&(length as u32).to_le_bytes());
    let mut reference = Shake256::default();
    reference.update(&prefix);
    let chunk = vec![0; 65_537];
    for offset in (0..length).step_by(chunk.len()) {
        reference.update(&chunk[..chunk.len().min(length - offset)]);
    }
    let mut expected = [0; 64];
    reference.finalize_xof().read(&mut expected);
    for chunk in [4093, 1 << 20] {
        assert_eq!(
            zero_coordinate(
                FheKeyCommitmentHasher::for_registration(&poll, &credential, profile, &salt)
                    .unwrap(),
                chunk
            ),
            expected
        );
    }
    for (other_owner, other_poll, other_runtime, other_salt) in [
        (
            *Credential::from_seed([9; 32]).signing_public(),
            poll.identity(),
            poll.runtime(),
            salt,
        ),
        (*credential.signing_public(), [9; 64], poll.runtime(), salt),
        (*credential.signing_public(), poll.identity(), [9; 64], salt),
        (
            *credential.signing_public(),
            poll.identity(),
            poll.runtime(),
            [9; 64],
        ),
    ] {
        assert_ne!(
            zero_coordinate(
                FheKeyCommitmentHasher::new(
                    other_poll,
                    other_runtime,
                    &other_owner,
                    profile,
                    &other_salt
                )
                .unwrap(),
                1 << 20
            ),
            expected
        );
    }
}

#[test]
fn malformed_or_incomplete_coordinate_cannot_finish_or_resume() {
    let poll = poll(3, 2);
    let credential = Credential::from_seed([7; 32]);
    let profile = Profile::new(3, 2).unwrap();
    let create =
        || FheKeyCommitmentHasher::for_registration(&poll, &credential, profile, &[8; 64]).unwrap();
    assert!(create().finish().is_err());
    for (offset, bytes) in [(1, vec![0]), (0, vec![]), (0, vec![0; (1 << 20) + 1])] {
        let mut hash = create();
        assert!(hash.push(offset, &bytes).is_err());
        assert!(hash.push(0, &[0]).is_err());
        assert!(hash.finish().is_err());
    }
    let width = profile.ciphertext_modulus().to_bytes().len() + 1;
    for sign in [0, 1] {
        let mut hash = create();
        let mut coefficient = vec![sign];
        coefficient.extend(&hash.half_modulus);
        hash.push(0, &coefficient[..3]).unwrap();
        hash.push(3, &coefficient[3..]).unwrap();
        zero_coordinate(hash, 4093);
    }
    for bytes in [
        {
            let mut value = vec![0; width];
            value[0] = 1;
            value
        },
        {
            let mut value = vec![0; width];
            value[0] = 2;
            value
        },
        {
            let mut value = vec![255; width];
            value[0] = 0;
            value
        },
    ] {
        let mut hash = create();
        hash.push(0, &bytes[..1]).unwrap();
        assert!(hash.push(1, &bytes[1..]).is_err());
        assert!(hash.finish().is_err());
    }
}
