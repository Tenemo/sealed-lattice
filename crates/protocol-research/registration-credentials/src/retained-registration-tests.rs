use super::*;
use crate::registration::CHUNK_LIMIT;
use crate::{
    SIGNATURE_BYTES,
    foundation::{
        StabilizedDisplayText,
        ceremony::{Manifest, OptionDefinition},
        normalize_username,
    },
    poll::{PollDraft, verify_poll},
    registration::KEY_BYTES,
};
use parallel_work::ProtocolHash;

struct Registration {
    poll: VerifiedPoll,
    credential: Credential,
    header: Vec<u8>,
    key: Vec<u8>,
    verified: VerifiedRegistration,
}

// A member's registration of an organizer's poll under the runtime,
// with a key whose hash its header names, as its verifier accepted it.
fn registration(runtime: [u8; 64], seed: u8) -> Registration {
    let text = |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
    let options = (0..2)
        .map(|index| {
            OptionDefinition::new(
                index,
                format!("option-{index}"),
                text(&format!("Option {index}")),
            )
            .unwrap()
        })
        .collect();
    let draft = PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 10).unwrap();
    let mut organizer = Credential::from_seed([1; 32]);
    let packet = organizer.create_poll(draft, runtime, [5; 32]).unwrap();
    let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
    let mut credential = Credential::from_seed([seed; 32]);
    let key: Vec<u8> = (0..KEY_BYTES / 21)
        .flat_map(|index| {
            let mut value = [0; 21];
            value[1] = (index as u8) ^ seed;
            value
        })
        .collect();
    let header = RegistrationHeader {
        username: normalize_username(b"Participant").unwrap(),
        poll: poll.identity(),
        runtime,
        signing_public: *credential.signing_public(),
        recipient_key_hash: ProtocolHash::digest(&key),

        fhe_key_commitments: vec![[7; 64]; crate::source_binding::fhe_key_families(&poll).len()],
    };
    let header = header.encode().unwrap();
    let body = crate::BodyDigest::from_header(&header, poll.identity(), poll.runtime()).unwrap();
    let signature = credential.sign_registration(body).unwrap();
    let mut verifier = RegistrationVerifier::new(&poll, &header, &signature).unwrap();
    for part in key.chunks(CHUNK_LIMIT) {
        verifier.push_key(part).unwrap();
    }
    verifier.finish_key().unwrap();
    let verified = verifier.finish().unwrap();
    Registration {
        header,
        verified,
        poll,
        credential,
        key,
    }
}

// A verifier of the header that has taken the key, as the host streams
// them before the retained copy.
fn keyed(poll: &VerifiedPoll, header: &[u8], key: &[u8]) -> RegistrationVerifier {
    let mut verifier = RegistrationVerifier::new(poll, header, &[0; SIGNATURE_BYTES]).unwrap();
    for part in key.chunks(CHUNK_LIMIT) {
        verifier.push_key(part).unwrap();
    }
    verifier.finish_key().unwrap();
    verifier
}

// The restored registration is the verified one, from the header and
// the key alone.
#[test]
fn retained_registrations_restore_the_verified_registration() {
    let registration = registration([4; 64], 7);
    let retained = registration
        .verified
        .retain(&registration.credential, &registration.poll)
        .unwrap();
    assert_eq!(retained.len(), RETAINED_REGISTRATION_BYTES);
    let restored = keyed(&registration.poll, &registration.header, &registration.key)
        .restore(&registration.credential, &registration.poll, &retained)
        .unwrap();
    assert_eq!(restored.header().encode().unwrap(), registration.header);
    assert_eq!(restored.body_digest(), registration.verified.body_digest());
    assert_eq!(restored.public_key(), registration.key);
}

// Only the credential the header names retains the registration, and
// only it restores the exact retained bytes, for the same poll and
// runtime, the same header and the key that header names.
#[test]
fn retained_registrations_bind_the_credential_poll_header_and_exact_bytes() {
    let registration = registration([4; 64], 7);
    let (poll, credential) = (&registration.poll, &registration.credential);
    let retained = registration.verified.retain(credential, poll).unwrap();
    let refused = |credential: &Credential, poll: &VerifiedPoll, retained: &[u8]| {
        keyed(poll, &registration.header, &registration.key)
            .restore(credential, poll, retained)
            .is_err()
    };
    assert!(!refused(credential, poll, &retained));
    // Another credential.
    let other = Credential::from_seed([8; 32]);
    assert!(registration.verified.retain(&other, poll).is_err());
    assert!(refused(&other, poll, &retained));
    // The same member's registration under a poll of another runtime.
    let foreign = super::tests::registration([5; 64], 7);
    assert!(
        registration
            .verified
            .retain(&foreign.credential, &foreign.poll)
            .is_err()
    );
    assert!(
        keyed(&foreign.poll, &foreign.header, &foreign.key)
            .restore(&foreign.credential, &foreign.poll, &retained)
            .is_err()
    );
    // Another header of the same credential and key.
    let mut header = RegistrationHeader::decode_prefix(&registration.header)
        .unwrap()
        .0;
    header.username = normalize_username(b"Another participant").unwrap();
    assert!(
        keyed(poll, &header.encode().unwrap(), &registration.key)
            .restore(credential, poll, &retained)
            .is_err()
    );
    // Every changed, missing or extra byte.
    for position in [0, 31, 63, 64, retained.len() - 1] {
        let mut changed = retained.clone();
        changed[position] ^= 1;
        assert!(refused(credential, poll, &changed), "{position}");
    }
    assert!(refused(credential, poll, &retained[..retained.len() - 1]));
    assert!(refused(
        credential,
        poll,
        &[retained.as_slice(), &[0]].concat()
    ));
}

// The retained copy replaces the proof only after the exact key the
// header names, and never after proof bytes.
#[test]
fn restored_registrations_need_the_named_key_and_no_proof() {
    let registration = registration([4; 64], 7);
    let (poll, credential) = (&registration.poll, &registration.credential);
    let retained = registration.verified.retain(credential, poll).unwrap();
    let verifier =
        || RegistrationVerifier::new(poll, &registration.header, &[0; SIGNATURE_BYTES]).unwrap();
    // Before the key, and after a key with one changed byte.
    assert!(matches!(
        verifier().restore(credential, poll, &retained),
        Err(Error::Consumed)
    ));
    let mut changed = verifier();
    let mut key = registration.key.clone();
    key[KEY_BYTES / 2] ^= 1;
    for part in key.chunks(CHUNK_LIMIT) {
        changed.push_key(part).unwrap();
    }
    assert!(changed.finish_key().is_err());
    assert!(matches!(
        changed.restore(credential, poll, &retained),
        Err(Error::Consumed)
    ));
}
